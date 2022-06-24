package cmd

import (
	"context"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	psaApi "k8s.io/pod-security-admission/api"
)

func IgnoreNamespaceSelector(field string) string {
	ignoredNamespaces := []string{"kube-system", "kube-public", "kube-node-lease"}
	selectors := make([]fields.Selector, 0)
	for _, n := range ignoredNamespaces {
		selectors = append(selectors, fields.OneTermNotEqualSelector(field, n))
	}
	return fields.AndSelectors(selectors...).String()
}

func GetPods() *v1.PodList {
	listOptions := metav1.ListOptions{FieldSelector: IgnoreNamespaceSelector("metadata.namespace")}
	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), listOptions)
	if err != nil {
		panic(err.Error())
	}
	return pods
}

func GetPodsByNamespace(namespace string) *v1.PodList {
	listOptions := metav1.ListOptions{}
	pods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), listOptions)
	if err != nil {
		panic(err.Error())
	}
	return pods
}

func GetNamespaces() *v1.NamespaceList {
	listOptions := metav1.ListOptions{FieldSelector: IgnoreNamespaceSelector("metadata.name")}
	namespaces, err := clientset.CoreV1().Namespaces().List(context.TODO(), listOptions)
	if err != nil {
		panic(err.Error())
	}
	return namespaces
}

func ApplyPSSLevel(namespace *v1.Namespace, level psaApi.Level, control string) {
	namespace.Labels["pod-security.kubernetes.io/"+control] = string(level)
	namespace, err := clientset.CoreV1().Namespaces().Update(context.TODO(), namespace, metav1.UpdateOptions{})
	if err != nil {
		panic(err.Error())
	}
}
