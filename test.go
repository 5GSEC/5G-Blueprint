package main

import (
	"context"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"gopkg.in/yaml.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type WorkloadMap struct {
	Workload                string   `yaml:"Component Name"`
	WorkloadLabels          []string `yaml:"Workload Labels"`
	SensitiveAssetLocations []string `yaml:"Sensitive Asset Locations"`
	Egress                  []string `yaml:"Egress,omitempty"`
	Ingress                 []string `yaml:"Ingress,omitempty"`
	RiskDescription         string   `yaml:"Risk Description,omitempty"`
	Severity                string   `yaml:"Severity,omitempty"`
	Checkpoints             []string `yaml:"Checkpoints,omitempty"`
	RiskID                  string   `yaml:"Risk ID,omitempty"`
}

type Risk struct {
	RiskID          string   `yaml:"risk_id"`
	Workload        []string `yaml:"workload"`
	RiskDescription string   `yaml:"risk_description"`
	Severity        string   `yaml:"severity"`
	Checkpoints     []string `yaml:"checkpoints"`
}

type MergedData struct {
	WorkloadMap
	ComponentName   string   `yaml:"component_name"`
	RiskID          string   `yaml:"risk_id"`
	Workload        []string `yaml:"workload"`
	RiskDescription string   `yaml:"risk_description"`
	Severity        string   `yaml:"severity"`
	Checkpoints     []string `yaml:"checkpoints"`
}

func main() {
	// Read YAML file
	yamlFile, err := ioutil.ReadFile("oai-workload-map.yaml")
	if err != nil {
		log.Fatalf("Error reading YAML file: %v", err)
	}

	var components []WorkloadMap

	err = yaml.Unmarshal(yamlFile, &components)
	if err != nil {
		log.Fatalf("Error unmarshaling YAML: %v", err)
	}

	componentMap := make(map[string]WorkloadMap)

	for _, comp := range components {
		componentMap[comp.Workload] = comp
	}

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

	// mergedMap := mergeMaps(mapWorkloadToRisk(), componentMap)
	workMaps := mapWorkloadToRisk()

	mergedMap := mergeMaps(componentMap, workMaps)
	for workload, riskDetails := range mergedMap {
		fmt.Println(workload)
		fmt.Println("\n", riskDetails)

	}

	data, err := ioutil.ReadFile("risk_config.yaml")
	if err != nil {
		log.Fatalf("error reading YAML file: %v", err)
	}

	// Parse the YAML data into Go structs
	// var merged []MergedData
	var risks []Risk
	var FinalRisks []WorkloadMap
	err = yaml.Unmarshal(data, &risks)
	if err != nil {
		log.Fatalf("error unmarshalling YAML data: %v", err)
	}

	for _, details := range componentMap {

		Exist, err := verifyWorkloads(edgeclientset, coreclientset, details)
		if err != nil {
			panic(err.Error())
		}

		if Exist {

		}
	}
	_, err = verifyNetworkPolicy(edgeclientset, coreclientset, componentMap)
	if err != nil {
		fmt.Errorf("error checking pods in EDGE cluster: %v", err)
	}

	// finalMerged := mergeDuplicates(merged)

	// // Convert the struct to JSON
	// jsonData, err := json.MarshalIndent(finalMerged, "", "  ")
	// if err != nil {
	// 	fmt.Println("Error marshaling struct:", err)
	// 	return
	// }
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl := `
		<!DOCTYPE html>
		<html>
		<head>
			<style>
				.accordion {
					max-width: 800px;
					margin: 20px auto;
				}
				.accordion-header {
					background: #f4f4f4;
					padding: 15px;
					cursor: pointer;
					border: 1px solid #ddd;
					border-radius: 4px;
					margin-top: 5px;
				}
				.accordion-content {
					display: none;
					padding: 15px;
					border: 1px solid #ddd;
					border-top: none;
				}
				.severity-high { color: #dc3545; }
				.severity-medium { color: #ffc107; }
				.severity-low { color: #28a745; }
			</style>
		</head>
		<body>
			<div class="accordion">
				{{range .}}
				<div class="accordion-section">
					<div class="accordion-header" onclick="toggleAccordion(this)">
						{{.Workload}} - Risk ID: {{.RiskID}}
					</div>
					<div class="accordion-content">
						<h3>Risk Details</h3>
						<p><strong>Description:</strong> {{.RiskDescription}}</p>
						<p><strong>Severity:</strong> <span class="severity-{{.Severity}}">{{.Severity}}</span></p>
						
						{{if .WorkloadLabels}}
						<h4>Workload Labels</h4>
						<ul>
							{{range .WorkloadLabels}}
							<li>{{.}}</li>
							{{end}}
						</ul>
						{{end}}
		
						{{if .SensitiveAssetLocations}}
						<h4>Sensitive Asset Locations</h4>
						<ul>
							{{range .SensitiveAssetLocations}}
							<li>{{.}}</li>
							{{end}}
						</ul>
						{{end}}
		
						{{if .Egress}}
						<h4>Egress Rules</h4>
						<ul>
							{{range .Egress}}
							<li>{{.}}</li>
							{{end}}
						</ul>
						{{end}}
		
						{{if .Ingress}}
						<h4>Ingress Rules</h4>
						<ul>
							{{range .Ingress}}
							<li>{{.}}</li>
							{{end}}
						</ul>
						{{end}}
		
						{{if .Checkpoints}}
						<h4>Checkpoints</h4>
						<ul>
							{{range .Checkpoints}}
							<li>{{.}}</li>
							{{end}}
						</ul>
						{{end}}
					</div>
				</div>
				{{end}}
			</div>
		
			<script>
				function toggleAccordion(element) {
					const content = element.nextElementSibling;
					if (content.style.display === "block") {
						content.style.display = "none";
					} else {
						content.style.display = "block";
					}
				}
			</script>
		</body>
		</html>`
		t, err := template.New("accordion").Parse(tmpl)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, det := range mergedMap {
			Exist, err := verifyWorkloads(edgeclientset, coreclientset, det)
			if err != nil {
				panic(err.Error())
			}

			if Exist {
				FinalRisks = append(FinalRisks, det)
			}

		}

		err = t.Execute(w, FinalRisks)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	})

	http.ListenAndServe(":8080", nil)

}

func mergeDuplicates(slice []MergedData) []MergedData {
	result := []MergedData{}
	seen := make(map[string]bool)

	for _, risk := range slice {
		for _, labels := range risk.WorkloadLabels {
			if _, exists := seen[labels]; !exists {
				result = append(result, risk)
				seen[labels] = true
			}
		}
	}

	return result
}

func mergeMaps(map1 map[string]WorkloadMap, map2 map[string][]map[string]interface{}) map[string]WorkloadMap {
	mergedMap := make(map[string]WorkloadMap)

	for key, wlm := range map1 {
		if data, exists := map2[key]; exists {
			for _, item := range data {
				if labels, ok := item["Workload Labels"]; ok {
					wlm.WorkloadLabels = append(wlm.WorkloadLabels, labels.([]string)...)
				}
				if locations, ok := item["Sensitive Asset Locations"]; ok {
					wlm.SensitiveAssetLocations = append(wlm.SensitiveAssetLocations, locations.([]string)...)
				}
				if egress, ok := item["Egress"]; ok {
					wlm.Egress = append(wlm.Egress, egress.([]string)...)
				}
				if ingress, ok := item["Ingress"]; ok {
					wlm.Ingress = append(wlm.Ingress, ingress.([]string)...)
				}

				// Handle extra fields
				if riskDesc, ok := item["risk_description"]; ok {
					wlm.RiskDescription = riskDesc.(string)
				}
				if severity, ok := item["severity"]; ok {
					wlm.Severity = severity.(string)
				}
				if checkpoints, ok := item["checkpoints"]; ok {
					wlm.Checkpoints = append(wlm.Checkpoints, checkpoints.([]string)...)
				}
				if riskID, ok := item["risk_id"]; ok {
					wlm.RiskID = riskID.(string)
				}
			}
		}
		// Add the merged WorkloadMap to the result map
		mergedMap[key] = wlm
	}

	return mergedMap
}

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

func verifyWorkloads(edgeCientset *kubernetes.Clientset, coreClientset *kubernetes.Clientset, workload WorkloadMap) (bool, error) {

	// Create label selector from workload labels
	var labelSelector string
	for _, v := range workload.WorkloadLabels {
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

func verifyNetworkPolicy(edgeClientset *kubernetes.Clientset, coreClientset *kubernetes.Clientset, workload map[string]WorkloadMap) (bool, error) {
	edgeNetworkPolicies, err := edgeClientset.NetworkingV1().NetworkPolicies("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to list network policies: %v", err)
	}

	fmt.Println("CHECKING NETWORK POLICIES")

	for _, np := range edgeNetworkPolicies.Items {
		for work, details := range workload {
			for _, det := range details.WorkloadLabels {
				if !matchesLabelSelector(np.Spec.PodSelector.MatchLabels, det) {
					fmt.Println("Continuing cuz nothing found")
					continue
				}
				for _, egress := range np.Spec.Egress {
					for _, to := range egress.To {
						for _, egre := range details.Egress {
							component, exists := workload[egre]
							if !exists {
								fmt.Println("Component not found:", details.Workload)
								continue
							}
							for _, labels := range component.WorkloadLabels {
								if to.PodSelector != nil && matchesLabelSelector(to.PodSelector.MatchLabels, labels) {
									fmt.Printf("Policy %s for workload %s in EDGE cluster allows egress to pods with label %s\n",
										np.Name, work, labels)
								}
							}
						}
					}
				}
			}
		}
	}

	coreNetworkPolicies, err := coreClientset.NetworkingV1().NetworkPolicies("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to list network policies: %v", err)
	}

	for _, np := range coreNetworkPolicies.Items {
		for work, details := range workload {
			for _, det := range details.WorkloadLabels {
				if !matchesLabelSelector(np.Spec.PodSelector.MatchLabels, det) {
					fmt.Println("Continuing cuz nothing found")
					continue
				}
				for _, egress := range np.Spec.Egress {
					for _, to := range egress.To {
						for _, egre := range details.Egress {
							component, exists := workload[egre]
							if !exists {
								fmt.Println("Component not found:", details.Workload)
								continue
							}
							for _, labels := range component.WorkloadLabels {
								if to.PodSelector != nil && matchesLabelSelector(to.PodSelector.MatchLabels, labels) {
									fmt.Printf("Policy %s for workload %s in EDGE cluster allows egress to pods with label %s\n",
										np.Name, work, labels)
								}
							}
						}
					}
				}
			}
		}
	}

	return true, err
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
