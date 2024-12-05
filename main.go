package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"gopkg.in/yaml.v2"
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

	for _, info := range workloadMap {
		exists, err := verifyWorkloads(edgeclientset, coreclientset, info)
		if err != nil {
			panic(err.Error())
		}
		if exists {
			edgeNetwork, edgeWorkloads, err := verifyNetworkPolicy(edgeclientset, info, workloadMap)
			if err != nil {
				panic(err.Error())
			}
			fmt.Println("EDGE POLICY EXISTS OR NOT: ", edgeNetwork, "WORKLOAD: ", edgeWorkloads)
			coreNetwork, coreWorkloads, err := verifyNetworkPolicy(coreclientset, info, workloadMap)
			fmt.Println("CORE POLICY EXISTS OR NOT: ", coreNetwork, "WORKLOAD: ", coreWorkloads)
			// if network {
			// 	info.Checkpoint.EgressCheck = true

			// 	fmt.Println("Network policy does indeed exist for: ", name)
			// }

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

func verifyNetworkPolicy(clientset *kubernetes.Clientset, work Workload, workload map[string]Workload) (bool, Workload, error) {
	networkPolicies, err := clientset.NetworkingV1().NetworkPolicies("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return false, Workload{}, fmt.Errorf("failed to list network policies: %v", err)
	}
	var flag = false

	fmt.Println("CHECKING NETWORK POLICIES")

	for _, np := range networkPolicies.Items {
		// if !matchesLabelSelector(np.Spec.PodSelector.MatchLabels, det) {
		// 	fmt.Println("Continuing cuz nothing found")
		// 	continue
		// }

		for _, lab := range work.Labels {
			if !matchesLabelSelector(np.Spec.PodSelector.MatchLabels, lab) {
				fmt.Println("Continuing cuz nothing found")
				continue
			}
		}

		for _, egress := range np.Spec.Egress {
			for _, to := range egress.To {

				for work, details := range workload {
					for _, egre := range details.Egress {
						component, exists := workload[egre]
						if !exists {
							fmt.Println("To Pod Egress not found:", details.WorkloadName)
							continue
						}

						for _, labels := range component.Labels {
							if to.PodSelector != nil && matchesLabelSelector(to.PodSelector.MatchLabels, labels) {
								fmt.Printf("Policy %s for workload %s in cluster allows egress to pods with label %s\n",
									np.Name, work, labels)
								flag = true
								break
							}
						}
					}

				}
			}

		}
	}

	return flag, work, err
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
