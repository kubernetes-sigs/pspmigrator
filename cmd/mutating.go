package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/olekukonko/tablewriter"
	"github.com/kubernetes-sigs/pspmigrator"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var MutatingCmd = &cobra.Command{
	Use:   "mutating",
	Short: "Check if pods or PSP objects are mutating",
}

func initMutating() {
	podCmd := cobra.Command{
		Use:   "pod [name of pod]",
		Short: "Check if a pod is being mutated by a PSP policy",
		Run: func(cmd *cobra.Command, args []string) {
			// Examples for error handling:
			// - Use helper functions like e.g. errors.IsNotFound()
			// - And/or cast to StatusError and use its properties like e.g. ErrStatus.Message
			pod := args[0]
			podObj, err := clientset.CoreV1().Pods(Namespace).Get(context.TODO(), pod, metav1.GetOptions{})
			if errors.IsNotFound(err) {
				fmt.Printf("Pod %s in namespace %s not found\n", pod, Namespace)
			} else if statusError, isStatus := err.(*errors.StatusError); isStatus {
				fmt.Printf("Error getting pod %s in namespace %s: %v\n",
					pod, Namespace, statusError.ErrStatus.Message)
			} else if err != nil {
				panic(err.Error())
			} else {
				mutated, diff, err := pspmigrator.IsPodBeingMutatedByPSP(podObj, clientset)
				if err != nil {
					log.Println(err)
				}
				if pspName, ok := podObj.ObjectMeta.Annotations["kubernetes.io/psp"]; ok {
					fmt.Printf("Pod %v is mutated by PSP %v: %v, diff: %v\n", podObj.Name, pspName, mutated, diff)
					pspObj, err := clientset.PolicyV1beta1().PodSecurityPolicies().Get(context.TODO(), pspName, metav1.GetOptions{})
					if errors.IsNotFound(err) {
						fmt.Printf("PodSecurityPolicy %s not found\n", pspName)
					} else if statusError, isStatus := err.(*errors.StatusError); isStatus {
						fmt.Printf("Error getting PodSecurityPolicy %s: %v\n",
							pspName, statusError.ErrStatus.Message)
					} else if err != nil {
						panic(err.Error())
					} else {
						_, fields, annotations := pspmigrator.IsPSPMutating(pspObj)
						fmt.Printf("PSP profile %v has the following mutating fields: %v and annotations: %v\n", pspName, fields, annotations)
					}

				}
			}
		},
		Args: cobra.ExactArgs(1),
	}

	podCmd.Flags().StringVarP(&Namespace, "namespace", "n", "", "K8s namespace (required)")
	podCmd.MarkFlagRequired("namespace")

	podsCmd := cobra.Command{
		Use:   "pods",
		Short: "Check all pods across all namespaces in a cluster are being mutated by a PSP policy",
		Run: func(cmd *cobra.Command, args []string) {
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Name", "Namespace", "Mutated", "PSP"})
			pods := GetPods()
			fmt.Printf("There are %d pods in the cluster\n", len(pods.Items))
			for _, pod := range pods.Items {
				if pspName, ok := pod.ObjectMeta.Annotations["kubernetes.io/psp"]; ok {
					mutated, _, err := pspmigrator.IsPodBeingMutatedByPSP(&pod, clientset)
					if err != nil {
						log.Println("error occured checking if pod is mutated:", err)
					}
					table.Append([]string{pod.Name, pod.Namespace, strconv.FormatBool(mutated), pspName})
				}
			}
			table.Render() // Send output
		},
		Args: cobra.NoArgs,
	}

	pspCmd := cobra.Command{
		Use:   "psp [name of PSP object]",
		Short: "Check if a PSP object is potentially mutating pods",
		Run: func(cmd *cobra.Command, args []string) {
			// Examples for error handling:
			// - Use helper functions like e.g. errors.IsNotFound()
			// - And/or cast to StatusError and use its properties like e.g. ErrStatus.Message
			pspName := args[0]
			pspObj, err := clientset.PolicyV1beta1().PodSecurityPolicies().Get(context.TODO(), pspName, metav1.GetOptions{})
			if errors.IsNotFound(err) {
				fmt.Printf("PodSecurityPolicy %s not found\n", pspName)
			} else if statusError, isStatus := err.(*errors.StatusError); isStatus {
				fmt.Printf("Error getting PodSecurityPolicy %s: %v\n",
					pspName, statusError.ErrStatus.Message)
			} else if err != nil {
				panic(err.Error())
			} else {
				_, fields, annotations := pspmigrator.IsPSPMutating(pspObj)
				fmt.Printf("PSP profile %v has the following mutating fields: %v and annotations: %v\n", pspName, fields, annotations)
			}

		},
		Args: cobra.ExactArgs(1),
	}

	MutatingCmd.AddCommand(&podCmd)
	MutatingCmd.AddCommand(&podsCmd)
	MutatingCmd.AddCommand(&pspCmd)
}
