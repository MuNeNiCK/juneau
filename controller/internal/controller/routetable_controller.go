/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"math"
	"net"
	"slices"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	juneauloutresmev1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const defaultVpcName = "default"
const servicePublicAnnotation = "juneau.loutres.me/public"

// RouteTableReconciler reconciles a RouteTable object
type RouteTableReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=juneau.loutres.me,resources=routetables,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=routetables/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=juneau.loutres.me,resources=routetables/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the RouteTable object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.2/pkg/reconcile
func (r *RouteTableReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var resource juneauloutresmev1alpha1.RouteTable
	if err := r.Get(ctx, req.NamespacedName, &resource); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		logger.Error(err, "unable to get RouteTable", "name", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if !resource.ObjectMeta.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	var statusRoutes []juneauloutresmev1alpha1.Route
	var subnetNames []string

	var subnets juneauloutresmev1alpha1.SubnetList
	if err := r.List(ctx, &subnets, client.MatchingFields{"spec.vpc": resource.Spec.Vpc}); err != nil {
		return ctrl.Result{}, err
	}
	for _, subnet := range subnets.Items {
		statusRoutes = appendConnectedRoute(statusRoutes, subnet)
		subnetNames = append(subnetNames, subnet.Name)
	}
	if resource.Spec.Vpc == defaultVpcName {
		var tenantSubnets juneauloutresmev1alpha1.SubnetList
		if err := r.List(ctx, &tenantSubnets); err != nil {
			return ctrl.Result{}, err
		}
		for _, subnet := range tenantSubnets.Items {
			if subnet.Spec.Vpc == defaultVpcName {
				continue
			}
			statusRoutes = appendConnectedRoute(statusRoutes, subnet)
		}
	} else {
		var err error
		statusRoutes, err = r.appendPublicServiceRoutes(ctx, statusRoutes)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	for _, route := range resource.Spec.Routes {
		if rt := getRoute(statusRoutes, route.Dst); rt == nil {
			var subnet string
			if route.Via.Type == juneauloutresmev1alpha1.ViaConnnected {
				continue
			} else if route.Via.Type == juneauloutresmev1alpha1.ViaEndpoint {
				var nwep juneauloutresmev1alpha1.NetworkEndpoint
				if err := r.Get(ctx, client.ObjectKey{Name: route.Via.Endpoint}, &nwep); err != nil {
					if errors.IsNotFound(err) {
						// TODO: set condition
						continue
					}
					return ctrl.Result{}, err
				}
				if !slices.Contains(subnetNames, nwep.Spec.Subnet) {
					// TODO: set condition
					continue
				}
				subnet = nwep.Spec.Subnet
			}
			route.Subnet = subnet
			statusRoutes = append(statusRoutes, route)
		}
	}
	resource.Status.Routes = statusRoutes

	if resource.Status.TableID == 0 {
		var id uint32 = 1
		for {
			if id == math.MaxUint32 {
				// TODO: set condition
				return ctrl.Result{}, nil
			}
			id++

			var tableList juneauloutresmev1alpha1.RouteTableList
			if err := r.List(ctx, &tableList, client.MatchingFields{"status.tableID": strconv.FormatUint(uint64(id), 10)}); err != nil {
				return ctrl.Result{}, err
			}

			if len(tableList.Items) == 0 {
				break
			}
		}

		resource.Status.TableID = id
	}

	if err := r.Status().Update(ctx, &resource); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func appendConnectedRoute(routes []juneauloutresmev1alpha1.Route, subnet juneauloutresmev1alpha1.Subnet) []juneauloutresmev1alpha1.Route {
	if getRoute(routes, subnet.Spec.CIDR) != nil {
		return routes
	}

	return append(routes, juneauloutresmev1alpha1.Route{
		Dst:    subnet.Spec.CIDR,
		Subnet: subnet.Name,
		Via: juneauloutresmev1alpha1.RouteVia{
			Type: juneauloutresmev1alpha1.ViaConnnected,
		},
	})
}

func appendExactConnectedRoute(routes []juneauloutresmev1alpha1.Route, dst string, subnet string) []juneauloutresmev1alpha1.Route {
	if getRoute(routes, dst) != nil {
		return routes
	}

	return append(routes, juneauloutresmev1alpha1.Route{
		Dst:    dst,
		Subnet: subnet,
		Via: juneauloutresmev1alpha1.RouteVia{
			Type: juneauloutresmev1alpha1.ViaConnnected,
		},
	})
}

func (r *RouteTableReconciler) appendPublicServiceRoutes(ctx context.Context, routes []juneauloutresmev1alpha1.Route) ([]juneauloutresmev1alpha1.Route, error) {
	var services corev1.ServiceList
	if err := r.List(ctx, &services); err != nil {
		return nil, err
	}

	var endpointSlices discoveryv1.EndpointSliceList
	if err := r.List(ctx, &endpointSlices); err != nil {
		return nil, err
	}

	var networkEndpoints juneauloutresmev1alpha1.NetworkEndpointList
	if err := r.List(ctx, &networkEndpoints); err != nil {
		return nil, err
	}

	var subnets juneauloutresmev1alpha1.SubnetList
	if err := r.List(ctx, &subnets); err != nil {
		return nil, err
	}

	subnetByName := make(map[string]juneauloutresmev1alpha1.Subnet, len(subnets.Items))
	for _, subnet := range subnets.Items {
		subnetByName[subnet.Name] = subnet
	}

	networkEndpointByIP := make(map[string]juneauloutresmev1alpha1.NetworkEndpoint, len(networkEndpoints.Items))
	for _, networkEndpoint := range networkEndpoints.Items {
		ip := ipFromAddress(networkEndpoint.Spec.Address)
		if ip == nil {
			continue
		}
		networkEndpointByIP[ip.String()] = networkEndpoint
	}

	endpointSlicesByService := make(map[string][]discoveryv1.EndpointSlice)
	for _, endpointSlice := range endpointSlices.Items {
		serviceName := endpointSlice.Labels[discoveryv1.LabelServiceName]
		if serviceName == "" {
			continue
		}
		endpointSlicesByService[namespacedName(endpointSlice.Namespace, serviceName)] = append(
			endpointSlicesByService[namespacedName(endpointSlice.Namespace, serviceName)],
			endpointSlice,
		)
	}

	for _, service := range services.Items {
		if !servicePublic(&service) {
			continue
		}

		backends, ownerVPC, err := resolveRouteServiceBackends(
			&service,
			endpointSlicesByService[namespacedName(service.Namespace, service.Name)],
			networkEndpointByIP,
			subnetByName,
		)
		if err != nil || ownerVPC != defaultVpcName {
			continue
		}

		for _, backend := range backends {
			routes = appendExactConnectedRoute(routes, backend.ip+"/32", backend.subnet)
		}
	}

	return routes, nil
}

type routeServiceBackend struct {
	ip     string
	subnet string
}

func resolveRouteServiceBackends(service *corev1.Service, endpointSlices []discoveryv1.EndpointSlice, networkEndpointByIP map[string]juneauloutresmev1alpha1.NetworkEndpoint, subnetByName map[string]juneauloutresmev1alpha1.Subnet) ([]routeServiceBackend, string, error) {
	backends := make([]routeServiceBackend, 0)
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

				if _, ok := seen[ip.String()]; ok {
					continue
				}
				seen[ip.String()] = struct{}{}
				backends = append(backends, routeServiceBackend{
					ip:     ip.String(),
					subnet: networkEndpoint.Spec.Subnet,
				})
			}
		}
	}

	return backends, ownerVPC, nil
}

func servicePublic(service *corev1.Service) bool {
	value := service.Annotations[servicePublicAnnotation]
	return value == "true" || value == "1" || value == "TRUE" || value == "True"
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

func getRoute(routes []juneauloutresmev1alpha1.Route, dst string) *juneauloutresmev1alpha1.Route {
	for _, route := range routes {
		if route.Dst == dst {
			return &route
		}
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RouteTableReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&juneauloutresmev1alpha1.RouteTable{},
		"status.tableID",
		func(obj client.Object) []string {
			table := obj.(*juneauloutresmev1alpha1.RouteTable)
			if table.Status.TableID == 0 {
				return nil
			}
			return []string{strconv.FormatUint(uint64(table.Status.TableID), 10)}
		},
	); err != nil {
		return fmt.Errorf("failed to set up field indexer for RouteTable.status.tableID: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&juneauloutresmev1alpha1.RouteTable{}).
		Watches(
			&juneauloutresmev1alpha1.Subnet{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
				subnet, ok := obj.(*juneauloutresmev1alpha1.Subnet)
				if !ok || subnet.Spec.Vpc == "" {
					return nil
				}

				reqs := []reconcile.Request{{
					NamespacedName: client.ObjectKey{Name: subnet.Spec.Vpc},
				}}
				if subnet.Spec.Vpc != defaultVpcName {
					reqs = append(reqs, reconcile.Request{
						NamespacedName: client.ObjectKey{Name: defaultVpcName},
					})
				}
				return reqs
			}),
		).
		Watches(
			&corev1.Service{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
				return r.enqueueAllRouteTables(ctx)
			}),
		).
		Watches(
			&discoveryv1.EndpointSlice{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
				return r.enqueueAllRouteTables(ctx)
			}),
		).
		Watches(
			&juneauloutresmev1alpha1.NetworkEndpoint{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
				return r.enqueueAllRouteTables(ctx)
			}),
		).
		Named("routetable").
		Complete(r)
}

func (r *RouteTableReconciler) enqueueAllRouteTables(ctx context.Context) []reconcile.Request {
	var routeTables juneauloutresmev1alpha1.RouteTableList
	if err := r.List(ctx, &routeTables); err != nil {
		return nil
	}

	reqs := make([]reconcile.Request, 0, len(routeTables.Items))
	for _, routeTable := range routeTables.Items {
		reqs = append(reqs, reconcile.Request{
			NamespacedName: client.ObjectKey{Name: routeTable.Name},
		})
	}
	return reqs
}
