package main

import (
	"os"
	"sort"

	"gopkg.in/yaml.v2"
)

var tmplStr = `
<!DOCTYPE html>
<html>
<head>
    <title>O-RAN Risk Assessment</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .accordion {
            width: 100%;
            max-width: 1000px;
            margin: 0 auto;
        }
        details {
            margin-bottom: 15px;
            border: 1px solid #ddd;
            border-radius: 8px;
            background-color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        summary {
            padding: 15px;
            background-color: #f8f9fa;
            cursor: pointer;
            font-weight: bold;
            border-radius: 8px 8px 0 0;
        }
        summary:hover {
            background-color: #e9ecef;
        }
        .content {
            padding: 20px;
            line-height: 1.6;
        }
        .severity-High {
            color: #dc3545;
            font-weight: bold;
        }
        h4 {
            color: #495057;
            margin-top: 15px;
            margin-bottom: 10px;
        }
        .checkpoint {
            background-color: #f8f9fa;
            padding: 10px;
            margin: 5px 0;
            border-radius: 4px;
        }
        .risk-section {
            border-left: 4px solid #007bff;
            margin: 10px 0;
            padding: 10px;
            background-color: #f8f9fa;
        }
        .checkpoint .status {
            margin-right: 10px;
        }
        .status-pass {
            color: #28a745;
        }
        .status-fail {
            color: #dc3545;
        }
    </style>
</head>
<body>
    <div class="accordion">
        {{range .}}
            <details>
                <summary>{{.WorkloadName}}</summary>
                <div class="content">
                    {{range .Risks}}
                        <div class="risk-section">
                            <p><strong>Risk ID:</strong> {{.RiskID}}</p>
                            <p><strong>Risk Description:</strong> {{.RiskDescription}}</p>
                            <p><strong>Severity:</strong> <span class="severity-{{.Severity}}">{{.Severity}}</span></p>
                            <h4>Checkpoints:</h4>
                            {{with .Checkpoints.CHK_TLS}}
                                <div class="checkpoint">
                                    <strong>TLS Check:</strong> 
                                    {{range .}}
                                        <div>
                                            <span class="status {{if .Status }}status-pass{{else}}status-fail{{end}}">
                                                {{if  .Status }}✓{{else}}✗{{end}}
                                            </span>
                                            {{.Description}}
                                        </div>
                                    {{end}}
                                </div>
                            {{end}}
                            {{with .Checkpoints.CHK_POLP_EGRESS}}
                                <div class="checkpoint">
                                    <strong>Egress Policy Check:</strong>
                                    {{range .}}
                                        <div>
                                            <span class="status {{if  .Status }}status-pass{{else}}status-fail{{end}}">
                                                {{if  .Status }}✓{{else}}✗{{end}}
                                            </span>
                                            {{.Description}}
                                        </div>
                                    {{end}}
                                </div>
                            {{end}}
                            {{with .Checkpoints.CHK_SENSITIVE_ASSETS}}
                                <div class="checkpoint">
                                    <strong>Sensitive Assets Check:</strong>
                                    {{range .}}
                                        <div>
                                            <span class="status {{if  .Status }}status-pass{{else}}status-fail{{end}}">
                                                {{if  .Status }}✓{{else}}✗{{end}}
                                            </span>
                                            {{.Description}}
                                        </div>
                                    {{end}}
                                </div>
                            {{end}}
                        </div>
                    {{end}}
                </div>
            </details>
        {{end}}
    </div>
</body>
</html>`

func loadRisks(filename string) ([]Risk, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var risks []Risk
	err = yaml.Unmarshal(data, &risks)
	if err != nil {
		return nil, err
	}

	return risks, nil
}

func groupRisksByWorkload(risks []Risk) []WorkloadRisks {
	workloadMap := make(map[string][]Risk)

	for _, risk := range risks {
		for _, workload := range risk.Workload {
			workloadMap[workload] = append(workloadMap[workload], risk)
		}
	}

	var result []WorkloadRisks
	for workload, risks := range workloadMap {
		result = append(result, WorkloadRisks{
			WorkloadName: workload,
			Risks:        risks,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].WorkloadName < result[j].WorkloadName
	})

	return result
}
