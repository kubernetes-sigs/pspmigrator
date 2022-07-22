/*
Copyright 2022 The Kubernetes Authors.

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

package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/kubernetes-sigs/pspmigrator"
	"github.com/manifoldco/promptui"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	psaapi "k8s.io/pod-security-admission/api"
)

var DryRun bool

func init() {
	MigrateCmd.Flags().BoolVarP(&DryRun, "dry-run", "d", true, "Set dry run to true to not apply any changes")
}

var MigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Interactive command to migrate from PSP to PSA ",
	Long: `The interactive command will help with setting a suggested a
	Suggested Pod Security Standard for each namespace. In addition, it also
	checks whether a PSP object is mutating pods in every namespace.`,
	Run: func(cmd *cobra.Command, args []string) {
		pods, err := GetPods()
		if err != nil {
			log.Fatalln("Error getting pods", err.Error())
		}
		fmt.Println("Checking if any pods are being mutated by a PSP object")
		mutatedPods := make([]v1.Pod, 0)
		for _, pod := range pods.Items {
			mutated, _, err := pspmigrator.IsPodBeingMutatedByPSP(&pod, clientset)
			if err != nil {
				log.Fatalln(err)
			}
			if mutated {
				mutatedPods = append(mutatedPods, pod)
			}
		}
		if len(mutatedPods) > 0 {
			fmt.Println("The table below shows the pods that were mutated by a PSP object")
			// TODO: Group pods by controller to remove duplicate pods
			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Pod Name", "Namespace", "PSP"})
			for _, pod := range mutatedPods {
				if pspName, ok := pod.ObjectMeta.Annotations["kubernetes.io/psp"]; ok {
					table.Append([]string{pod.Name, pod.Namespace, pspName})
				}
			}
			table.Render()
			pod := mutatedPods[0]
			fmt.Printf("There were %v pods mutated. Please modify the PodSpec such that PSP no longer needs to mutate your pod.\n", len(mutatedPods))
			fmt.Printf("You can run `pspmigrator mutating pod %v -n %v` to learn more why and how your pod is being mutated. ", pod.Name, pod.Namespace)
			fmt.Printf("Please re-run the tool again after you've modified your PodSpecs.\n")
			os.Exit(1)
		}

		namespaces, err := GetNamespaces()
		if err != nil {
			log.Fatalln("Error getting namespaces:", err.Error())
		}
		for _, namespace := range namespaces.Items {
			// Check if namespace already has psa labels
			if NamespaceHasPSALabels(&namespace) {
				log.Printf("The namespace %v already has PSA labels set. So skipping....\n", namespace.Name)
				log.Printf("The following labels are currently set on the %v namespace.\n Labels: %#v\n",
					namespace.Name, namespace.Labels)
				continue
			}
			suggestions := make(map[psaapi.Level]bool)
			podList, err := GetPodsByNamespace(namespace.Name)
			if err != nil {
				log.Printf("Error getting pods for namespace %v. Error: %v\n", namespace.Name, err.Error())
				log.Println("Continuing with next namespace")
				continue
			}
			pods := podList.Items
			if len(pods) == 0 {
				fmt.Printf("There are no pods running in namespace %v. Skipping and going to the next one.\n", namespace.Name)
				continue
			}
			for _, pod := range pods {
				level, err := pspmigrator.SuggestedPodSecurityStandard(&pod)
				if err != nil {
					fmt.Println("error occured checking the suggested pod security standard", err)
					fmt.Println("Continuing with the next namespace due to error with ", namespace.Name)
					continue
				}
				suggestions[level] = true
			}
			var suggested psaapi.Level
			switch {
			case suggestions["privileged"]:
				suggested = psaapi.LevelPrivileged
			case suggestions["baseline"]:
				suggested = psaapi.LevelBaseline
			case suggestions["restricted"]:
				suggested = psaapi.LevelRestricted
			}
			fmt.Printf("Suggest using %v in namespace %v\n", suggested, namespace.Name)
			if DryRun == true {
				fmt.Printf("In dry-run mode so not applying any changes. You can run this ")
				fmt.Printf("command again with --dry-run=false to apply %v on namespace %v\n", suggested, namespace.Name)
			} else {
				skipStr := "skip, continue with next namespace"
				// TODO add ability to set this as a flag for all namespaces instead of prompting per namespace
				prompt := promptui.Select{
					Label: fmt.Sprintf("Select control mode for %v on namespace %v", suggested, namespace.Name),
					Items: []string{"enforce", "audit", skipStr},
				}
				_, control, err := prompt.Run()
				if err != nil {
					fmt.Println("error occured getting enforcement mode", err)
				}
				if control == skipStr {
					continue
				}
				if err := ApplyPSSLevel(&namespace, suggested, control); err != nil {
					log.Printf("Error applying %v on namespace %v. Error: %v\n", suggested, namespace.Name, err.Error())
				}
				fmt.Printf("Applied pod security level %v on namespace %v in %v control mode\n", suggested, namespace.Name, control)
				fmt.Printf("Review the labels by running `kubectl get ns %v -o yaml`\n", namespace.Name)
			}
		}
		fmt.Println("Done with migrating namespaces with pods to PSA")

	},
}
