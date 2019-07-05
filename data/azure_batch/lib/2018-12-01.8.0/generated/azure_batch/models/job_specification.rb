# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_12_01_8_0
  module Models
    #
    # Specifies details of the jobs to be created on a schedule.
    #
    #
    class JobSpecification

      include MsRestAzure

      # @return [Integer] The priority of jobs created under this schedule.
      # Priority values can range from -1000 to 1000, with -1000 being the
      # lowest priority and 1000 being the highest priority. The default value
      # is 0. This priority is used as the default for all jobs under the job
      # schedule. You can update a job's priority after it has been created
      # using by using the update job API.
      attr_accessor :priority

      # @return [String] The display name for jobs created under this schedule.
      # The name need not be unique and can contain any Unicode characters up
      # to a maximum length of 1024.
      attr_accessor :display_name

      # @return [Boolean] Whether tasks in the job can define dependencies on
      # each other. The default is false.
      attr_accessor :uses_task_dependencies

      # @return [OnAllTasksComplete] The action the Batch service should take
      # when all tasks in a job created under this schedule are in the
      # completed state. Note that if a job contains no tasks, then all tasks
      # are considered complete. This option is therefore most commonly used
      # with a Job Manager task; if you want to use automatic job termination
      # without a Job Manager, you should initially set onAllTasksComplete to
      # noaction and update the job properties to set onAllTasksComplete to
      # terminatejob once you have finished adding tasks. The default is
      # noaction. Possible values include: 'noAction', 'terminateJob'
      attr_accessor :on_all_tasks_complete

      # @return [OnTaskFailure] The action the Batch service should take when
      # any task fails in a job created under this schedule. A task is
      # considered to have failed if it have failed if has a failureInfo. A
      # failureInfo is set if the task completes with a non-zero exit code
      # after exhausting its retry count, or if there was an error starting the
      # task, for example due to a resource file download error. The default is
      # noaction. Possible values include: 'noAction',
      # 'performExitOptionsJobAction'
      attr_accessor :on_task_failure

      # @return [JobNetworkConfiguration] The network configuration for the
      # job.
      attr_accessor :network_configuration

      # @return [JobConstraints] The execution constraints for jobs created
      # under this schedule.
      attr_accessor :constraints

      # @return [JobManagerTask] The details of a Job Manager task to be
      # launched when a job is started under this schedule. If the job does not
      # specify a Job Manager task, the user must explicitly add tasks to the
      # job using the Task API. If the job does specify a Job Manager task, the
      # Batch service creates the Job Manager task when the job is created, and
      # will try to schedule the Job Manager task before scheduling other tasks
      # in the job.
      attr_accessor :job_manager_task

      # @return [JobPreparationTask] The Job Preparation task for jobs created
      # under this schedule. If a job has a Job Preparation task, the Batch
      # service will run the Job Preparation task on a compute node before
      # starting any tasks of that job on that compute node.
      attr_accessor :job_preparation_task

      # @return [JobReleaseTask] The Job Release task for jobs created under
      # this schedule. The primary purpose of the Job Release task is to undo
      # changes to compute nodes made by the Job Preparation task. Example
      # activities include deleting local files, or shutting down services that
      # were started as part of job preparation. A Job Release task cannot be
      # specified without also specifying a Job Preparation task for the job.
      # The Batch service runs the Job Release task on the compute nodes that
      # have run the Job Preparation task.
      attr_accessor :job_release_task

      # @return [Array<EnvironmentSetting>] A list of common environment
      # variable settings. These environment variables are set for all tasks in
      # jobs created under this schedule (including the Job Manager, Job
      # Preparation and Job Release tasks). Individual tasks can override an
      # environment setting specified here by specifying the same setting name
      # with a different value.
      attr_accessor :common_environment_settings

      # @return [PoolInformation] The pool on which the Batch service runs the
      # tasks of jobs created under this schedule.
      attr_accessor :pool_info

      # @return [Array<MetadataItem>] A list of name-value pairs associated
      # with each job created under this schedule as metadata. The Batch
      # service does not assign any meaning to metadata; it is solely for the
      # use of user code.
      attr_accessor :metadata


      #
      # Mapper for JobSpecification class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'JobSpecification',
          type: {
            name: 'Composite',
            class_name: 'JobSpecification',
            model_properties: {
              priority: {
                client_side_validation: true,
                required: false,
                serialized_name: 'priority',
                type: {
                  name: 'Number'
                }
              },
              display_name: {
                client_side_validation: true,
                required: false,
                serialized_name: 'displayName',
                type: {
                  name: 'String'
                }
              },
              uses_task_dependencies: {
                client_side_validation: true,
                required: false,
                serialized_name: 'usesTaskDependencies',
                type: {
                  name: 'Boolean'
                }
              },
              on_all_tasks_complete: {
                client_side_validation: true,
                required: false,
                serialized_name: 'onAllTasksComplete',
                type: {
                  name: 'Enum',
                  module: 'OnAllTasksComplete'
                }
              },
              on_task_failure: {
                client_side_validation: true,
                required: false,
                serialized_name: 'onTaskFailure',
                type: {
                  name: 'Enum',
                  module: 'OnTaskFailure'
                }
              },
              network_configuration: {
                client_side_validation: true,
                required: false,
                serialized_name: 'networkConfiguration',
                type: {
                  name: 'Composite',
                  class_name: 'JobNetworkConfiguration'
                }
              },
              constraints: {
                client_side_validation: true,
                required: false,
                serialized_name: 'constraints',
                type: {
                  name: 'Composite',
                  class_name: 'JobConstraints'
                }
              },
              job_manager_task: {
                client_side_validation: true,
                required: false,
                serialized_name: 'jobManagerTask',
                type: {
                  name: 'Composite',
                  class_name: 'JobManagerTask'
                }
              },
              job_preparation_task: {
                client_side_validation: true,
                required: false,
                serialized_name: 'jobPreparationTask',
                type: {
                  name: 'Composite',
                  class_name: 'JobPreparationTask'
                }
              },
              job_release_task: {
                client_side_validation: true,
                required: false,
                serialized_name: 'jobReleaseTask',
                type: {
                  name: 'Composite',
                  class_name: 'JobReleaseTask'
                }
              },
              common_environment_settings: {
                client_side_validation: true,
                required: false,
                serialized_name: 'commonEnvironmentSettings',
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
              pool_info: {
                client_side_validation: true,
                required: true,
                serialized_name: 'poolInfo',
                default_value: {},
                type: {
                  name: 'Composite',
                  class_name: 'PoolInformation'
                }
              },
              metadata: {
                client_side_validation: true,
                required: false,
                serialized_name: 'metadata',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'MetadataItemElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'MetadataItem'
                      }
                  }
                }
              }
            }
          }
        }
      end
    end
  end
end
