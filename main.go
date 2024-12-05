package main

import (
	"context"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"
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
	RiskID          string        `yaml:"risk_id"`
	Workload        []string      `yaml:"workload"`
	RiskDescription string        `yaml:"risk_description"`
	Severity        string        `yaml:"severity"`
	Checkpoints     CheckpointMap `yaml:"checkpoints"`
}

// Define the structure for the workload
type Workload struct {
	WorkloadName            string     `yaml:"workload_name"`
	Labels                  []string   `yaml:"labels"` // Labels are key-value pairs
	SensitiveAssetLocations []string   `yaml:"sensitive_asset_locations"`
	Egress                  []string   `yaml:"egress,omitempty"`
	Ingress                 []string   `yaml:"ingress,omitempty"`
	Checkpoint              Checkpoint `yaml:"checkpoints"`
}

// Define the top-level structure
type workloadConfig struct {
	Workloads []Workload `yaml:"workloads"`
}

type Checkpoint struct {
	Description string `yaml:"description"`
	Status      bool   `yaml:"status"`
}

type CheckpointMap struct {
	CHK_TLS              []Checkpoint `yaml:"CHK_TLS"`
	CHK_POLP_EGRESS      []Checkpoint `yaml:"CHK_POLP_INGRESS"`
	CHK_SENSITIVE_ASSETS []Checkpoint `yaml:"CHK_SENSITIVE_ASSETS"`
}

type WorkloadRisks struct {
	WorkloadName string
	Risks        []Risk
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

	risks, err := loadRisks("risk_config.yaml")
	if err != nil {
		log.Fatalf("Failed to load risks: %v", err)
	}

	// tmpl := template.Must(template.New("accordion").Parse(tmplStr))
	workloadRisks := groupRisksByWorkload(risks)

	// Create a map with workload_name as the key
	workloadMap := make(map[string]Workload)
	for _, workload := range entries.Workloads {
		workloadMap[workload.WorkloadName] = workload
	}

	for i, risk := range workloadRisks {
		for _, info := range workloadMap {
			exists, err := verifyWorkloads(edgeclientset, coreclientset, info)
			if err != nil {
				panic(err.Error())
			}
			if exists {

				edgeLabel, edgekspCheck, err := checkSensitiveDirs(edgeconfig, info.SensitiveAssetLocations, info.Labels)
				if err != nil {
					panic(err.Error())
				}

				// coreLabel, coreKSPCheck, er := checkSensitiveDirs(coreconfig. info.SensitiveAssetLocations, info.Labels)
				if reflect.DeepEqual(info.Labels, edgeLabel) && risk.WorkloadName == info.WorkloadName && edgekspCheck {
					for j, riskList := range risk.Risks {
						for k := range riskList.Checkpoints.CHK_SENSITIVE_ASSETS {
							workloadRisks[i].Risks[j].Checkpoints.CHK_SENSITIVE_ASSETS[k].Status = true
						}
					}
				}

				coreNetwork, coreLabel, err := verifyNetworkPolicy(coreclientset, info, workloadMap)

				fmt.Println("CORE Network Policy there?:", coreNetwork, " For Label: ", coreLabel)

				if reflect.DeepEqual(info.Labels, coreLabel) && risk.WorkloadName == info.WorkloadName && coreNetwork {
					for j, riskList := range risk.Risks {
						for k := range riskList.Checkpoints.CHK_SENSITIVE_ASSETS {
							workloadRisks[i].Risks[j].Checkpoints.CHK_POLP_EGRESS[k].Status = true
						}
					}
				}

				// 	fmt.Println("Network policy does indeed exist for: ", name)
				// }

			}
		}
	}

	tmpl := template.Must(template.New("accordion").Parse(tmplStr))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		workloadRisks := groupRisksByWorkload(risks)
		err := tmpl.Execute(w, workloadRisks)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))

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

func verifyNetworkPolicy(clientset *kubernetes.Clientset, w Workload, workload map[string]Workload) (bool, []string, error) {
	networkPolicies, err := clientset.NetworkingV1().NetworkPolicies("").List(context.TODO(), metav1.ListOptions{}) // add label selector filter
	if err != nil {
		return false, nil, fmt.Errorf("failed to list network policies: %v", err)
	}

	var rLabel []string
	match := false

	for _, np := range networkPolicies.Items {
		for _, egresscheck := range w.Egress {
			component, exists := workload[egresscheck]
			if !exists {
				continue
			}
			for _, egress := range np.Spec.Egress {
				for _, to := range egress.To {
					for _, lab := range component.Labels {
						if matchesLabelSelector(to.PodSelector.MatchLabels, lab) {
							match = true
							rLabel = w.Labels
							break
						}
					}
				}
				if match {
					break
				}
			}
			if !match {
				return false, nil, nil
			}
		}
	}

	return match, rLabel, err
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
