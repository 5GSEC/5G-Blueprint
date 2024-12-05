package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"gopkg.in/yaml.v2"
	v1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// type WorkloadMap struct {
// 	Workload                string   `yaml:"Component Name"`
// 	WorkloadLabels          []string `yaml:"Workload Labels"`
// 	SensitiveAssetLocations []string `yaml:"Sensitive Asset Locations"`
// 	Egress                  []string `yaml:"Egress,omitempty"`
// 	Ingress                 []string `yaml:"Ingress,omitempty"`
// 	RiskDescription         string   `yaml:"Risk Description,omitempty"`
// 	Severity                string   `yaml:"Severity,omitempty"`
// 	Checkpoints             []string `yaml:"Checkpoints,omitempty"`
// 	RiskID                  string   `yaml:"Risk ID,omitempty"`
// }

type Risk struct {
	RiskID          string   `yaml:"risk_id"`
	Workload        []string `yaml:"workload"`
	RiskDescription string   `yaml:"risk_description"`
	Severity        string   `yaml:"severity"`
	Checkpoints     []string `yaml:"checkpoints"`
}

// Define the structure for the workload
type Workload struct {
	WorkloadName            string      `yaml:"workload_name"`
	Labels                  []string    `yaml:"labels"` // Labels are key-value pairs
	SensitiveAssetLocations []string    `yaml:"sensitive_asset_locations"`
	Egress                  []string    `yaml:"egress,omitempty"`
	Ingress                 []string    `yaml:"ingress,omitempty"`
	Checkpoint              Checkpoints `yaml:"checkpoints"`
}

// Define the top-level structure
type workloadConfig struct {
	Workloads []Workload `yaml:"workloads"`
}

type Checkpoints struct {
	TLSCheck    bool
	EgressCheck bool
	PolicyCheck bool
}

func main() {

	edgeconfig, err := clientcmd.BuildConfigFromFlags("", "/home/ubuntu/.kube/edge-kubeconfig")
	if err != nil {
		panic(err.Error())
	}

	coreconfig, err := clientcmd.BuildConfigFromFlags("", "/home/ubuntu/.kube/core-kubeconfig")
	if err != nil {
		panic(err.Error())
	}

	edgeclientset, err := kubernetes.NewForConfig(edgeconfig)
	if err != nil {
		panic(err.Error())
	}

	coreclientset, err := kubernetes.NewForConfig(coreconfig)
	if err != nil {
		panic(err.Error())
	}

	oaiConfig, err := ioutil.ReadFile("oai-workload-map.yaml")
	if err != nil {
		panic(err)
	}

	var entries workloadConfig
	err = yaml.Unmarshal(oaiConfig, &entries)
	if err != nil {
		panic(err)
	}

	// Create a map with workload_name as the key
	workloadMap := make(map[string]Workload)
	for _, workload := range entries.Workloads {
		workloadMap[workload.WorkloadName] = workload
	}

	network, err := verifyNetworkPolicy(edgeclientset, coreclientset, workloadMap)
	if err != nil {
		panic(err.Error())
	}
	fmt.Println(network)

	for name, info := range workloadMap {
		exists, err := verifyWorkloads(edgeclientset, coreclientset, info)
		if err != nil {
			panic(err.Error())
		}
		if exists {

			if network {
				info.Checkpoint.EgressCheck = true

				fmt.Println("Network policy does indeed exist for: ", name)
			}

		}
	}

}

// func mergeDuplicates(slice []MergedData) []MergedData {
// 	result := []MergedData{}
// 	seen := make(map[string]bool)

// 	for _, risk := range slice {
// 		for _, labels := range risk.WorkloadLabels {
// 			if _, exists := seen[labels]; !exists {
// 				result = append(result, risk)
// 				seen[labels] = true
// 			}
// 		}
// 	}

// 	return result
// }

// func mergeMaps(map1 map[string]WorkloadMap, map2 map[string][]map[string]interface{}) map[string]WorkloadMap {
// 	mergedMap := make(map[string]WorkloadMap)

// 	for key, wlm := range map1 {
// 		if data, exists := map2[key]; exists {
// 			for _, item := range data {
// 				if labels, ok := item["Workload Labels"]; ok {
// 					wlm.WorkloadLabels = append(wlm.WorkloadLabels, labels.([]string)...)
// 				}
// 				if locations, ok := item["Sensitive Asset Locations"]; ok {
// 					wlm.SensitiveAssetLocations = append(wlm.SensitiveAssetLocations, locations.([]string)...)
// 				}
// 				if egress, ok := item["Egress"]; ok {
// 					wlm.Egress = append(wlm.Egress, egress.([]string)...)
// 				}
// 				if ingress, ok := item["Ingress"]; ok {
// 					wlm.Ingress = append(wlm.Ingress, ingress.([]string)...)
// 				}

// 				// Handle extra fields
// 				if riskDesc, ok := item["risk_description"]; ok {
// 					wlm.RiskDescription = riskDesc.(string)
// 				}
// 				if severity, ok := item["severity"]; ok {
// 					wlm.Severity = severity.(string)
// 				}
// 				if checkpoints, ok := item["checkpoints"]; ok {
// 					wlm.Checkpoints = append(wlm.Checkpoints, checkpoints.([]string)...)
// 				}
// 				if riskID, ok := item["risk_id"]; ok {
// 					wlm.RiskID = riskID.(string)
// 				}
// 			}
// 		}
// 		// Add the merged WorkloadMap to the result map
// 		mergedMap[key] = wlm
// 	}

// 	return mergedMap
// }

func mapWorkloadToRisk() map[string][]map[string]interface{} {

	data, err := ioutil.ReadFile("risk_config.yaml")
	if err != nil {
		log.Fatalf("error reading YAML file: %v", err)
	}

	workloadToRiskMapping := make(map[string][]map[string]interface{})

	// Parse the YAML data into Go structs
	var risks []Risk
	err = yaml.Unmarshal(data, &risks)
	if err != nil {
		log.Fatalf("error unmarshalling YAML data: %v", err)
	}

	for _, risk := range risks {
		for _, workload := range risk.Workload {
			workloadToRiskMapping[workload] = append(workloadToRiskMapping[workload], map[string]interface{}{
				"risk_id":          risk.RiskID,
				"risk_description": risk.RiskDescription,
				"severity":         risk.Severity,
				"checkpoints":      risk.Checkpoints,
			})
		}
	}

	return workloadToRiskMapping
}

func verifyWorkloads(edgeCientset *kubernetes.Clientset, coreClientset *kubernetes.Clientset, workload Workload) (bool, error) {

	// Create label selector from workload labels
	var labelSelector string
	for _, v := range workload.Labels {
		if labelSelector != "" {
			labelSelector += ","
		}
		labelSelector += v
	}

	// Check if pods with these labels exist in the namespace
	edgePods, err := edgeCientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return false, fmt.Errorf("error checking pods in EDGE cluster: %v", err)
	}

	corePods, err := coreClientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return false, fmt.Errorf("error checking pods in CORE cluster: %v", err)
	}

	if len(edgePods.Items) == 0 && len(corePods.Items) == 0 {
		return false, nil
	}

	return true, nil
}

func verifyNetworkPolicy(edgeClientset *kubernetes.Clientset, coreClientset *kubernetes.Clientset, workload map[string]Workload) (bool, error) {
	checkPolicies := func(networkPolicies *v1.NetworkPolicyList, clusterName string) (bool, error) {
		for _, np := range networkPolicies.Items {
			for work, details := range workload {
				for _, det := range details.Labels {
					if !matchesLabelSelector(np.Spec.PodSelector.MatchLabels, det) {
						fmt.Printf("Continuing in %s cluster because nothing matched PodSelector\n", clusterName)
						continue
					}

					for _, egress := range np.Spec.Egress {
						for _, to := range egress.To {
							for _, egre := range details.Egress {
								component, exists := workload[egre]
								if !exists {
									fmt.Printf("To Pod Egress not found in %s cluster for workload: %s\n", clusterName, details.WorkloadName)
									continue
								}
								for _, labels := range component.Labels {
									if to.PodSelector != nil && matchesLabelSelector(to.PodSelector.MatchLabels, labels) {
										fmt.Printf("Policy %s for workload %s in %s cluster allows egress to pods with label %s\n",
											np.Name, work, clusterName, labels)
										return true, nil
									}
								}
							}
						}
					}
				}
			}
		}
		return false, nil
	}

	fmt.Println("CHECKING NETWORK POLICIES")

	// Check Edge Cluster Policies
	edgeNetworkPolicies, err := edgeClientset.NetworkingV1().NetworkPolicies("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to list network policies in edge cluster: %v", err)
	}
	flag, err := checkPolicies(edgeNetworkPolicies, "EDGE")
	if err != nil || flag {
		return flag, err
	}

	// Check Core Cluster Policies
	coreNetworkPolicies, err := coreClientset.NetworkingV1().NetworkPolicies("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to list network policies in core cluster: %v", err)
	}
	flag, err = checkPolicies(coreNetworkPolicies, "CORE")
	return flag, err
}

func matchesLabelSelector(matchLabels map[string]string, targetLabel string) bool {
	for key, value := range matchLabels {
		label := fmt.Sprintf("%s=%s", key, value)
		if strings.Contains(targetLabel, label) {
			return true
		}
	}
	return false
}
