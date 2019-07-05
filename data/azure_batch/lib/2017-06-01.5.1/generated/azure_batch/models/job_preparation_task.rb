# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_06_01_5_1
  module Models
    #
    # A Job Preparation task to run before any tasks of the job on any given
    # compute node.

    # You can use Job Preparation to prepare a compute node to run tasks for
    # the job. Activities commonly performed in Job Preparation include:
    # Downloading common resource files used by all the tasks in the job. The
    # Job Preparation task can download these common resource files to the
    # shared location on the compute node. (AZ_BATCH_NODE_ROOT_DIR\shared), or
    # starting a local service on the compute node so that all tasks of that
    # job can communicate with it. If the Job Preparation task fails (that is,
    # exhausts its retry count before exiting with exit code 0), Batch will not
    # run tasks of this job on the compute node. The node remains ineligible to
    # run tasks of this job until it is reimaged. The node remains active and
    # can be used for other jobs. The Job Preparation task can run multiple
    # times on the same compute node. Therefore, you should write the Job
    # Preparation task to handle re-execution. If the compute node is rebooted,
    # the Job Preparation task is run again on the node before scheduling any
    # other task of the job, if rerunOnNodeRebootAfterSuccess is true or if the
    # Job Preparation task did not previously complete. If the compute node is
    # reimaged, the Job Preparation task is run again before scheduling any
    # task of the job.
    #
    class JobPreparationTask

      include MsRestAzure

      # @return [String] A string that uniquely identifies the Job Preparation
      # task within the job. The ID can contain any combination of alphanumeric
      # characters including hyphens and underscores and cannot contain more
      # than 64 characters. If you do not specify this property, the Batch
      # service assigns a default value of 'jobpreparation'. No other task in
      # the job can have the same ID as the Job Preparation task. If you try to
      # submit a task with the same id, the Batch service rejects the request
      # with error code TaskIdSameAsJobPreparationTask; if you are calling the
      # REST API directly, the HTTP status code is 409 (Conflict).
      attr_accessor :id

      # @return [String] The command line of the Job Preparation task. The
      # command line does not run under a shell, and therefore cannot take
      # advantage of shell features such as environment variable expansion. If
      # you want to take advantage of such features, you should invoke the
      # shell in the command line, for example using "cmd /c MyCommand" in
      # Windows or "/bin/sh -c MyCommand" in Linux.
      attr_accessor :command_line

      # @return [Array<ResourceFile>] A list of files that the Batch service
      # will download to the compute node before running the command line.
      # Files listed under this element are located in the task's working
      # directory.
      attr_accessor :resource_files

      # @return [Array<EnvironmentSetting>] A list of environment variable
      # settings for the Job Preparation task.
      attr_accessor :environment_settings

      # @return [TaskConstraints] Constraints that apply to the Job Preparation
      # task.
      attr_accessor :constraints

      # @return [Boolean] Whether the Batch service should wait for the Job
      # Preparation task to complete successfully before scheduling any other
      # tasks of the job on the compute node. A Job Preparation task has
      # completed successfully if it exits with exit code 0. If true and the
      # Job Preparation task fails on a compute node, the Batch service retries
      # the Job Preparation task up to its maximum retry count (as specified in
      # the constraints element). If the task has still not completed
      # successfully after all retries, then the Batch service will not
      # schedule tasks of the job to the compute node. The compute node remains
      # active and eligible to run tasks of other jobs. If false, the Batch
      # service will not wait for the Job Preparation task to complete. In this
      # case, other tasks of the job can start executing on the compute node
      # while the Job Preparation task is still running; and even if the Job
      # Preparation task fails, new tasks will continue to be scheduled on the
      # node. The default value is true.
      attr_accessor :wait_for_success

      # @return [UserIdentity] The user identity under which the Job
      # Preparation task runs. If omitted, the task runs as a
      # non-administrative user unique to the task on Windows nodes, or a
      # non-administrative user unique to the pool on Linux nodes.
      attr_accessor :user_identity

      # @return [Boolean] Whether the Batch service should rerun the Job
      # Preparation task after a compute node reboots. The Job Preparation task
      # is always rerun if a compute node is reimaged, or if the Job
      # Preparation task did not complete (e.g. because the reboot occurred
      # while the task was running). Therefore, you should always write a Job
      # Preparation task to be idempotent and to behave correctly if run
      # multiple times. The default value is true.
      attr_accessor :rerun_on_node_reboot_after_success


      #
      # Mapper for JobPreparationTask class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'JobPreparationTask',
          type: {
            name: 'Composite',
            class_name: 'JobPreparationTask',
            model_properties: {
              id: {
                client_side_validation: true,
                required: false,
                serialized_name: 'id',
                type: {
                  name: 'String'
                }
              },
              command_line: {
                client_side_validation: true,
                required: true,
                serialized_name: 'commandLine',
                type: {
                  name: 'String'
                }
              },
              resource_files: {
                client_side_validation: true,
                required: false,
                serialized_name: 'resourceFiles',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'ResourceFileElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'ResourceFile'
                      }
                  }
                }
              },
              environment_settings: {
                client_side_validation: true,
                required: false,
                serialized_name: 'environmentSettings',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'EnvironmentSettingElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'EnvironmentSetting'
                      }
                  }
                }
              },
              constraints: {
                client_side_validation: true,
                required: false,
                serialized_name: 'constraints',
                type: {
                  name: 'Composite',
                  class_name: 'TaskConstraints'
                }
              },
              wait_for_success: {
                client_side_validation: true,
                required: false,
                serialized_name: 'waitForSuccess',
                type: {
                  name: 'Boolean'
                }
              },
              user_identity: {
                client_side_validation: true,
                required: false,
                serialized_name: 'userIdentity',
                type: {
                  name: 'Composite',
                  class_name: 'UserIdentity'
                }
              },
              rerun_on_node_reboot_after_success: {
                client_side_validation: true,
                required: false,
                serialized_name: 'rerunOnNodeRebootAfterSuccess',
                type: {
                  name: 'Boolean'
                }
              }
            }
          }
        }
      end
    end
  end
end
