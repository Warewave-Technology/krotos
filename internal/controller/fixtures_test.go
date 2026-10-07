/*
Copyright 2026.

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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	krotosv1alpha1 "github.com/Warewave-Technology/krotos/api/v1alpha1"
)

const testNamespace = "default"

func validVaultConnectionSpec() krotosv1alpha1.VaultConnectionSpec {
	return krotosv1alpha1.VaultConnectionSpec{
		Address: "https://vault.example.com:8200",
		Auth: krotosv1alpha1.VaultAuth{
			Kubernetes: &krotosv1alpha1.VaultKubernetesAuth{Role: "krotos"},
		},
	}
}

func validRotationSpec() krotosv1alpha1.DatabaseCredentialRotationSpec {
	return krotosv1alpha1.DatabaseCredentialRotationSpec{
		Engine: krotosv1alpha1.EnginePostgreSQL,
		Database: krotosv1alpha1.DatabaseEndpoint{
			Host:     "pg.db.svc",
			Port:     5432,
			Database: "orders",
		},
		MasterCredentials: krotosv1alpha1.MasterCredentials{
			SecretRef: &krotosv1alpha1.SecretCredentialsReference{Name: "pg-master"},
		},
		Target: krotosv1alpha1.RotationTarget{
			Username: "orders_app",
			Vault: krotosv1alpha1.VaultTargetReference{
				VaultSecretReference: krotosv1alpha1.VaultSecretReference{
					ConnectionRef: "main-vault",
					Path:          "apps/orders/db",
				},
			},
		},
		Schedule: krotosv1alpha1.Schedule{Every: "30d"},
		Window: krotosv1alpha1.MaintenanceWindow{
			Timezone: "Europe/Istanbul",
			Start:    "02:00",
			Duration: metav1.Duration{Duration: 3 * time.Hour},
		},
	}
}
