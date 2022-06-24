package pspmigrator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	// Uncomment to load all auth plugins
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	//
	// Or uncomment to load specific auth plugins
	_ "k8s.io/client-go/plugin/pkg/client/auth/azure"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	_ "k8s.io/client-go/plugin/pkg/client/auth/openstack"
)

var (
	pspName   string = "pspmigrator-test"
	clientset *kubernetes.Clientset
)

type PSPOptions struct {
	Annotations            map[string]string
	DefaultAddCapabilities []string
	RunAsGroup             map[string]string
}

func GeneratePSPObject(options PSPOptions) v1beta1.PodSecurityPolicy {
	annotations := []byte("{}")
	if len(options.Annotations) > 0 {
		annotations, _ = json.Marshal(options.Annotations)
	}
	defaultAddCapabilities, err := json.Marshal(options.DefaultAddCapabilities)
	if err != nil {
		log.Panic(err)
	}
	pspObjJson := fmt.Sprintf(`{
		"metadata":{
			"name":"%s",
			"annotations": %s
		},
		"spec":{
			"defaultAddCapabilities":%s,
			"volumes":["*"],
			"seLinux":{"rule":"RunAsAny"},
			"runAsUser":{"rule":"RunAsAny"},
			"supplementalGroups":{"rule":"RunAsAny"},
			"fsGroup":{"rule":"RunAsAny"},
			"allowPrivilegeEscalation":true}
	}`, pspName, annotations, defaultAddCapabilities)
	fmt.Println(pspObjJson)
	var pspObj v1beta1.PodSecurityPolicy
	if err := json.Unmarshal([]byte(pspObjJson), &pspObj); err != nil {
		log.Panic(err)
	}
	return pspObj
}

func skipCI(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("Skipping testing in CI environment")
	}
}

func TestIsPSPNotMutating(t *testing.T) {
	pspObj := GeneratePSPObject(PSPOptions{})
	yes, fields, annotations := IsPSPMutating(&pspObj)
	fmt.Println("Mutating, fields, annotations:", yes, fields, annotations)
	if yes == true {
		t.Error("Mutating should be false but was true")
	}
	if len(fields) > 0 {
		t.Errorf("Expected fields to be empty, but got: %s", fields)
	}
	if len(annotations) > 0 {
		t.Errorf("Expected annoations to be empty, but got: %s", annotations)
	}
}

func TestIsPSPMutatingDefaultAddCapabilitiesOnly(t *testing.T) {
	pspObj := GeneratePSPObject(PSPOptions{DefaultAddCapabilities: []string{"CHOWN"}})
	yes, fields, annotations := IsPSPMutating(&pspObj)
	fmt.Println("Mutating, fields, annotations:", yes, fields, annotations)
	if yes == false {
		t.Error("Mutating should be true but was false")
	}
	if len(fields) != 1 {
		t.Errorf("Only DefaultAddCapabilities should have been reported as mutating, but got %s", fields)
	}
	if fields[0] != "DefaultAddCapabilities" {
		t.Errorf("Expected DefaultAddCapabilities to be mutating but got %s", fields[0])
	}
}

func TestIsPSPMutatingAnnotation(t *testing.T) {
	pspObj := GeneratePSPObject(PSPOptions{Annotations: map[string]string{"seccomp.security.alpha.kubernetes.io/defaultProfileName": "a"}})
	yes, fields, annotations := IsPSPMutating(&pspObj)
	fmt.Println("Mutating, fields, annotations:", yes, fields, annotations)
	if yes == false {
		t.Error("Mutating should be true but was false")
	}
}

func CreateClientSet() *kubernetes.Clientset {
	home := homedir.HomeDir()
	kubecfgPath := filepath.Join(home, ".kube", "config")
	config, err := clientcmd.BuildConfigFromFlags("", kubecfgPath)
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err)
	}
	return clientset

}

func SetupIntegrationTests(namespace string) {
	nsSpec := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	clientset.CoreV1().Namespaces().Create(context.Background(), nsSpec, metav1.CreateOptions{})

	// create Role and Rolebindings
	cr := rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "psptest-" + namespace},
		Rules: []rbacv1.PolicyRule{
			rbacv1.PolicyRule{
				APIGroups:     []string{"policy"},
				Resources:     []string{"podsecuritypolicies"},
				Verbs:         []string{"use"},
				ResourceNames: []string{pspName},
			},
		},
	}

	crb := rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "psptest-" + namespace},
		Subjects: []rbacv1.Subject{
			rbacv1.Subject{
				Kind:     "Group",
				Name:     "system:serviceaccounts:" + namespace,
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			APIGroup: "rbac.authorization.k8s.io",
			Name:     "psptest-" + namespace,
		},
	}
	clientset.RbacV1().ClusterRoles().Create(context.TODO(), &cr, metav1.CreateOptions{})
	clientset.RbacV1().ClusterRoleBindings().Create(context.TODO(), &crb, metav1.CreateOptions{})
}

func TeardownIntegrationTests(namespace string) {
	clientset.CoreV1().Namespaces().Delete(context.Background(), namespace, metav1.DeleteOptions{})
	clientset.PolicyV1beta1().PodSecurityPolicies().Delete(context.TODO(), pspName, metav1.DeleteOptions{})
	clientset.RbacV1().ClusterRoleBindings().Delete(context.TODO(), "psptest-"+namespace, metav1.DeleteOptions{})
	clientset.RbacV1().ClusterRoles().Delete(context.TODO(), "psptest-"+namespace, metav1.DeleteOptions{})

}

func int32Ptr(i int32) *int32 { return &i }

func CreateDeployment(name string) *appsv1.Deployment {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "demo",
				},
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "demo",
					},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:  "test",
							Image: "k8s.gcr.io/echoserver:1.4",
						},
					},
				},
			},
		},
	}
	return deployment
}

func TestIngreation(t *testing.T) {
	// TODO have CI that deploys K8s cluster for testing
	skipCI(t)

	clientset = CreateClientSet()
	cases := []struct {
		Name                   string
		DefaultAddCapabilities []string
		Annotations            map[string]string
		Expected               bool
	}{
		{"mutating-podspec", []string{"CHOWN"}, map[string]string{}, true},
		{"non-mutated-pod", []string{}, map[string]string{}, false},
		{"mutating-annotations", []string{}, map[string]string{
			"seccomp.security.alpha.kubernetes.io/defaultProfileName":  "runtime/default",
			"seccomp.security.alpha.kubernetes.io/allowedProfileNames": "*",
		}, true},
	}

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			// Create PSP policy
			pspObj := GeneratePSPObject(PSPOptions{
				DefaultAddCapabilities: tc.DefaultAddCapabilities,
				Annotations:            tc.Annotations,
			})
			clientset.PolicyV1beta1().PodSecurityPolicies().Create(context.TODO(), &pspObj, metav1.CreateOptions{})
			defer clientset.PolicyV1beta1().PodSecurityPolicies().Delete(context.TODO(), pspObj.Name, metav1.DeleteOptions{})

			namespace := "pspmigrator-" + tc.Name
			SetupIntegrationTests(namespace)
			defer TeardownIntegrationTests(namespace)

			deployment := CreateDeployment(namespace)
			result, err := clientset.AppsV1().Deployments(namespace).Create(context.TODO(), deployment, metav1.CreateOptions{})
			defer clientset.AppsV1().Deployments(namespace).Delete(context.TODO(), deployment.Name, metav1.DeleteOptions{})
			if err != nil {
				panic(err)
			}
			fmt.Printf("Created deployment %q.\n", result.GetObjectMeta().GetName())
			set := labels.Set{"app": "demo"}
			listOptions := metav1.ListOptions{LabelSelector: set.AsSelector().String()}
			var pods *v1.PodList
			for i := 0; i < 60; i++ {
				pods, err = clientset.CoreV1().Pods(namespace).List(context.TODO(), listOptions)
				if len(pods.Items) == 1 {
					break
				}
				time.Sleep(1 * time.Second)
			}
			if err != nil {
				t.Error(err.Error())
			}
			if len(pods.Items) != 1 {
				fmt.Println(pods, err)
				t.Errorf("Expected only a single pod, but got %v pods", len(pods.Items))
			}
			pod := pods.Items[0]
			mutated, diff, err := IsPodBeingMutatedByPSP(&pod, clientset)
			fmt.Println(diff)
			if mutated != tc.Expected {
				t.Errorf("Expected mutated to be %v but got %v", tc.Expected, mutated)
			}
		})
	}
}
