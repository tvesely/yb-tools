/*
Copyright © 2021 Yugabyte Support

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

package cmdutil

import (
	"fmt"
	"time"

	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/client/customer_tasks"
	"github.com/yugabyte/yb-tools/yugaware-client/pkg/client/swagger/models"
)

func WaitForTaskCompletion(ctx *YWClientContext, waitTask *models.YBPTask) (*models.CustomerTaskData, error) {
	params := customer_tasks.NewTasksListParams().
		WithContext(ctx).
		WithCUUID(ctx.Client.CustomerUUID())

	for {
		select {
		case <-time.After(1 * time.Second):
			resp, err := ctx.Client.PlatformAPIs.CustomerTasks.TasksList(params, ctx.Client.SwaggerAuth)
			if err != nil {
				return nil, err
			}
			finished, task, err := isTaskFinished(ctx, waitTask, resp.GetPayload())
			if err != nil {
				return nil, err
			}
			if finished {
				return task, nil
			}
		case <-ctx.Done():
			ctx.Log.Info("wait cancelled")
			return nil, nil
		}
	}
}

func isTaskFinished(ctx *YWClientContext, waitTask *models.YBPTask, taskmap map[string][]models.CustomerTaskData) (bool, *models.CustomerTaskData, error) {
	for _, tasklist := range taskmap {
		for _, task := range tasklist {
			if task.ID == waitTask.TaskUUID {
				if task.Status == "Success" {
					return true, &task, nil
				} else if task.Status != "Running" {
					return false, nil, fmt.Errorf("task failed: %s", task.Status)
				}

				ctx.Log.V(1).Info("task not complete", "task", task)
				break
			}
		}
	}
	return false, nil, nil
}
