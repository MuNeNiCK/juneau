package bpf

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const servicePublicAnnotation = "juneau.loutres.me/public"
const defaultVPCName = "default"

type resolvedServiceBackend struct {
	addr     uint32
	port     uint16
	portName string
	protocol corev1.Protocol
	vpc      string
}

func (m *Manager) UpsertService(ctx context.Context, svc *corev1.Service) error {
	zap.S().Infof("UpsertService called for %s/%s", svc.Namespace, svc.Name)
	return m.rebuildAllServiceMaps(ctx)
}

func (m *Manager) DeleteService(ctx context.Context, svc *corev1.Service) error {
	zap.S().Infof("DeleteService called for %s/%s", svc.Namespace, svc.Name)
	return m.rebuildAllServiceMaps(ctx)
}

func (m *Manager) UpsertEndpointSlice(ctx context.Context, endpointSlice *discoveryv1.EndpointSlice) error {
	zap.S().Infof("UpsertEndpointSlice called for %s/%s", endpointSlice.Namespace, endpointSlice.Name)
	return m.rebuildAllServiceMaps(ctx)
}

func (m *Manager) DeleteEndpointSlice(ctx context.Context, endpointSlice *discoveryv1.EndpointSlice) error {
	zap.S().Infof("DeleteEndpointSlice called for %s/%s", endpointSlice.Namespace, endpointSlice.Name)
	return m.rebuildAllServiceMaps(ctx)
}

func (m *Manager) rebuildAllServiceMaps(ctx context.Context) error {
	return m.rebuildAllServiceMapsWithNetworkEndpoint(ctx, nil, false)
}

func (m *Manager) rebuildAllServiceMapsWithNetworkEndpoint(ctx context.Context, hinted *juneauv1alpha1.NetworkEndpoint, deleted bool) error {
	var routeTables juneauv1alpha1.RouteTableList
	if err := m.client.List(ctx, &routeTables); err != nil {
		return err
	}

	var services corev1.ServiceList
	if err := m.client.List(ctx, &services); err != nil {
		return err
	}

	var endpointSlices discoveryv1.EndpointSliceList
	if err := m.client.List(ctx, &endpointSlices); err != nil {
		return err
	}

	var networkEndpoints juneauv1alpha1.NetworkEndpointList
	if err := m.client.List(ctx, &networkEndpoints); err != nil {
		return err
	}

	var subnets juneauv1alpha1.SubnetList
	if err := m.client.List(ctx, &subnets); err != nil {
		return err
	}

	serviceEntries := make(map[uint32]map[PodEgressServiceKey]PodEgressServiceVal, len(routeTables.Items))
	serviceBackendEntries := make(map[uint32]map[PodEgressServiceBackendKey]PodEgressServiceBackendVal, len(routeTables.Items))
	tableByVPC := make(map[string]uint32, len(routeTables.Items))
	nonDefaultTableIDs := make([]uint32, 0, len(routeTables.Items))
	for _, routeTable := range routeTables.Items {
		if routeTable.Status.TableID == 0 {
			continue
		}
		tableByVPC[routeTable.Spec.Vpc] = routeTable.Status.TableID
		serviceEntries[routeTable.Status.TableID] = make(map[PodEgressServiceKey]PodEgressServiceVal)
		serviceBackendEntries[routeTable.Status.TableID] = make(map[PodEgressServiceBackendKey]PodEgressServiceBackendVal)
		if routeTable.Spec.Vpc != defaultVPCName {
			nonDefaultTableIDs = append(nonDefaultTableIDs, routeTable.Status.TableID)
		}
	}

	subnetByName := make(map[string]juneauv1alpha1.Subnet, len(subnets.Items))
	for _, subnet := range subnets.Items {
		subnetByName[subnet.Name] = subnet
	}

	networkEndpointByIP := make(map[string]juneauv1alpha1.NetworkEndpoint, len(networkEndpoints.Items))
	for _, networkEndpoint := range networkEndpoints.Items {
		ip := ipFromAddress(networkEndpoint.Spec.Address)
		if ip == nil {
			continue
		}
		networkEndpointByIP[ip.String()] = networkEndpoint
	}
	if hinted != nil {
		ip := ipFromAddress(hinted.Spec.Address)
		if ip != nil {
			if deleted {
				delete(networkEndpointByIP, ip.String())
			} else {
				networkEndpointByIP[ip.String()] = *hinted
			}
		}
	}

	endpointSlicesByService := make(map[string][]discoveryv1.EndpointSlice)
	for _, endpointSlice := range endpointSlices.Items {
		serviceName := endpointSlice.Labels[discoveryv1.LabelServiceName]
		if serviceName == "" {
			continue
		}
		key := namespacedName(endpointSlice.Namespace, serviceName)
		endpointSlicesByService[key] = append(endpointSlicesByService[key], endpointSlice)
	}

	for _, service := range services.Items {
		clusterIP := ipFromAddress(service.Spec.ClusterIP)
		if clusterIP == nil {
			continue
		}

		serviceAddr, err := IPv4ToUint32(clusterIP)
		if err != nil {
			continue
		}

		backends, ownerVPC, err := resolveServiceBackends(
			&service,
			endpointSlicesByService[namespacedName(service.Namespace, service.Name)],
			networkEndpointByIP,
			subnetByName,
		)
		if err != nil {
			zap.S().Warnf("failed to resolve service backends for %s/%s: %v", service.Namespace, service.Name, err)
			continue
		}
		if len(backends) == 0 {
			continue
		}

		ownerTableID, ok := tableByVPC[ownerVPC]
		if !ok || ownerTableID == 0 {
			continue
		}

		targetTableIDs := []uint32{ownerTableID}
		if servicePublic(&service) && ownerVPC == defaultVPCName {
			targetTableIDs = append(targetTableIDs, nonDefaultTableIDs...)
		}

		for _, port := range service.Spec.Ports {
			proto, ok := serviceProtocol(port.Protocol)
			if !ok {
				continue
			}

			selectedBackends := selectBackendsForServicePort(port, backends)
			if len(selectedBackends) == 0 {
				continue
			}

			key := PodEgressServiceKey{
				Addr:  serviceAddr,
				Port:  uint16(port.Port),
				Proto: proto,
			}
			val := PodEgressServiceVal{
				BackendCount: uint16(len(selectedBackends)),
			}

			for _, tableID := range targetTableIDs {
				tableEntries, ok := serviceEntries[tableID]
				if !ok {
					tableEntries = make(map[PodEgressServiceKey]PodEgressServiceVal)
					serviceEntries[tableID] = tableEntries
				}
				tableEntries[key] = val

				backendEntries, ok := serviceBackendEntries[tableID]
				if !ok {
					backendEntries = make(map[PodEgressServiceBackendKey]PodEgressServiceBackendVal)
					serviceBackendEntries[tableID] = backendEntries
				}
				for slot, backend := range selectedBackends {
					backendEntries[PodEgressServiceBackendKey{
						Addr:  key.Addr,
						Port:  key.Port,
						Proto: key.Proto,
						Slot:  uint32(slot),
					}] = PodEgressServiceBackendVal{
						BackendAddr: backend.addr,
						BackendPort: backend.port,
					}
				}
			}
		}
	}

	for _, routeTable := range routeTables.Items {
		if routeTable.Status.TableID == 0 {
			continue
		}

		serviceInner, err := ebpf.NewMap(m.podEgressMapSpecs.ServiceInner.Copy())
		if err != nil {
			return err
		}

		for key, val := range serviceEntries[routeTable.Status.TableID] {
			if err := serviceInner.Update(&key, &val, ebpf.UpdateAny); err != nil {
				serviceInner.Close()
				return fmt.Errorf("update service inner map for table %d: %w", routeTable.Status.TableID, err)
			}
		}

		if err := m.podEgressObjs.ServiceMap.Update(uint32(routeTable.Status.TableID), uint32(serviceInner.FD()), ebpf.UpdateAny); err != nil {
			serviceInner.Close()
			return fmt.Errorf("update service map for table %d: %w", routeTable.Status.TableID, err)
		}

		if err := serviceInner.Close(); err != nil {
			return err
		}

		serviceBackendInner, err := ebpf.NewMap(m.podEgressMapSpecs.ServiceBackendInner.Copy())
		if err != nil {
			return err
		}

		for key, val := range serviceBackendEntries[routeTable.Status.TableID] {
			if err := serviceBackendInner.Update(&key, &val, ebpf.UpdateAny); err != nil {
				serviceBackendInner.Close()
				return fmt.Errorf("update service backend inner map for table %d: %w", routeTable.Status.TableID, err)
			}
		}

		if err := m.podEgressObjs.ServiceBackendMap.Update(uint32(routeTable.Status.TableID), uint32(serviceBackendInner.FD()), ebpf.UpdateAny); err != nil {
			serviceBackendInner.Close()
			return fmt.Errorf("update service backend map for table %d: %w", routeTable.Status.TableID, err)
		}

		if err := serviceBackendInner.Close(); err != nil {
			return err
		}
	}

	return nil
}

func resolveServiceBackends(service *corev1.Service, endpointSlices []discoveryv1.EndpointSlice, networkEndpointByIP map[string]juneauv1alpha1.NetworkEndpoint, subnetByName map[string]juneauv1alpha1.Subnet) ([]resolvedServiceBackend, string, error) {
	backends := make([]resolvedServiceBackend, 0)
	seen := make(map[string]struct{})
	ownerVPC := ""

	for _, endpointSlice := range endpointSlices {
		for _, endpoint := range endpointSlice.Endpoints {
			if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
				continue
			}

			for _, address := range endpoint.Addresses {
				ip := net.ParseIP(address)
				if ip == nil || ip.To4() == nil {
					continue
				}

				networkEndpoint, ok := networkEndpointByIP[ip.String()]
				if !ok {
					continue
				}

				subnet, ok := subnetByName[networkEndpoint.Spec.Subnet]
				if !ok {
					continue
				}

				if ownerVPC == "" {
					ownerVPC = subnet.Spec.Vpc
				} else if ownerVPC != subnet.Spec.Vpc {
					return nil, "", fmt.Errorf("service %s/%s spans multiple VPCs", service.Namespace, service.Name)
				}

				for _, port := range endpointSlice.Ports {
					if port.Port == nil {
						continue
					}

					protocol := corev1.ProtocolTCP
					if port.Protocol != nil {
						protocol = *port.Protocol
					}

					portName := ""
					if port.Name != nil {
						portName = *port.Name
					}

					key := fmt.Sprintf("%s/%d/%s/%s", ip.String(), *port.Port, protocol, portName)
					if _, ok := seen[key]; ok {
						continue
					}
					seen[key] = struct{}{}

					addr, err := IPv4ToUint32(ip)
					if err != nil {
						continue
					}

					backends = append(backends, resolvedServiceBackend{
						addr:     addr,
						port:     uint16(*port.Port),
						portName: portName,
						protocol: protocol,
						vpc:      subnet.Spec.Vpc,
					})
				}
			}
		}
	}

	return backends, ownerVPC, nil
}

func selectBackendsForServicePort(servicePort corev1.ServicePort, backends []resolvedServiceBackend) []resolvedServiceBackend {
	protocol := servicePort.Protocol
	if protocol == "" {
		protocol = corev1.ProtocolTCP
	}

	protocolBackends := make([]resolvedServiceBackend, 0, len(backends))
	for _, backend := range backends {
		if backend.protocol == protocol {
			protocolBackends = append(protocolBackends, backend)
		}
	}
	if len(protocolBackends) == 0 {
		return nil
	}

	if servicePort.Name != "" {
		matched := make([]resolvedServiceBackend, 0, len(protocolBackends))
		for _, backend := range protocolBackends {
			if backend.portName == servicePort.Name {
				matched = append(matched, backend)
			}
		}
		if len(matched) > 0 {
			sortResolvedServiceBackends(matched)
			return matched
		}
	}

	if servicePort.TargetPort.Type == intstr.String && servicePort.TargetPort.StrVal != "" {
		matched := make([]resolvedServiceBackend, 0, len(protocolBackends))
		for _, backend := range protocolBackends {
			if backend.portName == servicePort.TargetPort.StrVal {
				matched = append(matched, backend)
			}
		}
		if len(matched) > 0 {
			sortResolvedServiceBackends(matched)
			return matched
		}
	}

	if servicePort.TargetPort.Type == intstr.Int && servicePort.TargetPort.IntValue() != 0 {
		matched := make([]resolvedServiceBackend, 0, len(protocolBackends))
		for _, backend := range protocolBackends {
			if backend.port == uint16(servicePort.TargetPort.IntValue()) {
				matched = append(matched, backend)
			}
		}
		if len(matched) > 0 {
			sortResolvedServiceBackends(matched)
			return matched
		}
	}

	matched := make([]resolvedServiceBackend, 0, len(protocolBackends))
	for _, backend := range protocolBackends {
		if backend.port == uint16(servicePort.Port) {
			matched = append(matched, backend)
		}
	}
	if len(matched) > 0 {
		sortResolvedServiceBackends(matched)
		return matched
	}

	sortResolvedServiceBackends(protocolBackends)
	return protocolBackends
}

func sortResolvedServiceBackends(backends []resolvedServiceBackend) {
	sort.Slice(backends, func(i, j int) bool {
		if backends[i].addr != backends[j].addr {
			return backends[i].addr < backends[j].addr
		}
		if backends[i].port != backends[j].port {
			return backends[i].port < backends[j].port
		}
		return backends[i].portName < backends[j].portName
	})
}

func serviceProtocol(protocol corev1.Protocol) (uint8, bool) {
	switch protocol {
	case "", corev1.ProtocolTCP:
		return 6, true
	case corev1.ProtocolUDP:
		return 17, true
	default:
		return 0, false
	}
}

func servicePublic(service *corev1.Service) bool {
	value := strings.TrimSpace(service.Annotations[servicePublicAnnotation])
	return strings.EqualFold(value, "true") || value == "1"
}

func namespacedName(namespace, name string) string {
	return namespace + "/" + name
}

func ipFromAddress(address string) net.IP {
	if address == "" || address == corev1.ClusterIPNone {
		return nil
	}

	ip := net.ParseIP(address)
	if ip != nil {
		return ip.To4()
	}

	ip, _, err := net.ParseCIDR(address)
	if err != nil {
		return nil
	}
	return ip.To4()
}
