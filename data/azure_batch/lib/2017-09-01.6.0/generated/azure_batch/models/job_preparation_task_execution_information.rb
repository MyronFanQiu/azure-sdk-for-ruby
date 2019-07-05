# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_09_01_6_0
  module Models
    #
    # Contains information about the execution of a Job Preparation task on a
    # compute node.
    #
    #
    class JobPreparationTaskExecutionInformation

      include MsRestAzure

      # @return [DateTime] The time at which the task started running. If the
      # task has been restarted or retried, this is the most recent time at
      # which the task started running.
      attr_accessor :start_time

      # @return [DateTime] The time at which the Job Preparation task
      # completed. This property is set only if the task is in the Completed
      # state.
      attr_accessor :end_time

      # @return [JobPreparationTaskState] The current state of the Job
      # Preparation task on the compute node. Possible values include:
      # 'running', 'completed'
      attr_accessor :state

      # @return [String] The root directory of the Job Preparation task on the
      # compute node. You can use this path to retrieve files created by the
      # task, such as log files.
      attr_accessor :task_root_directory

      # @return [String] The URL to the root directory of the Job Preparation
      # task on the compute node.
      attr_accessor :task_root_directory_url

      # @return [Integer] The exit code of the program specified on the task
      # command line. This parameter is returned only if the task is in the
      # completed state. The exit code for a process reflects the specific
      # convention implemented by the application developer for that process.
      # If you use the exit code value to make decisions in your code, be sure
      # that you know the exit code convention used by the application process.
      # Note that the exit code may also be generated by the compute node
      # operating system, such as when a process is forcibly terminated.
      attr_accessor :exit_code

      # @return [TaskContainerExecutionInformation] Information about the
      # container under which the task is executing. This property is set only
      # if the task runs in a container context.
      attr_accessor :container_info

      # @return [TaskFailureInformation] Information describing the task
      # failure, if any. This property is set only if the task is in the
      # completed state and encountered a failure.
      attr_accessor :failure_info

      # @return [Integer] The number of times the task has been retried by the
      # Batch service. Task application failures (non-zero exit code) are
      # retried, pre-processing errors (the task could not be run) and file
      # upload errors are not retried. The Batch service will retry the task up
      # to the limit specified by the constraints. Task application failures
      # (non-zero exit code) are retried, pre-processing errors (the task could
      # not be run) and file upload errors are not retried. The Batch service
      # will retry the task up to the limit specified by the constraints.
      attr_accessor :retry_count

      # @return [DateTime] The most recent time at which a retry of the Job
      # Preparation task started running. This property is set only if the task
      # was retried (i.e. retryCount is nonzero). If present, this is typically
      # the same as startTime, but may be different if the task has been
      # restarted for reasons other than retry; for example, if the compute
      # node was rebooted during a retry, then the startTime is updated but the
      # lastRetryTime is not.
      attr_accessor :last_retry_time

      # @return [TaskExecutionResult] The result of the task execution. If the
      # value is 'failed', then the details of the failure can be found in the
      # failureInfo property. Possible values include: 'success', 'failure'
      attr_accessor :result


      #
      # Mapper for JobPreparationTaskExecutionInformation class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'JobPreparationTaskExecutionInformation',
          type: {
            name: 'Composite',
            class_name: 'JobPreparationTaskExecutionInformation',
            model_properties: {
              start_time: {
                client_side_validation: true,
                required: true,
                serialized_name: 'startTime',
                type: {
                  name: 'DateTime'
                }
              },
              end_time: {
                client_side_validation: true,
                required: false,
                serialized_name: 'endTime',
                type: {
                  name: 'DateTime'
                }
              },
              state: {
                client_side_validation: true,
                required: true,
                serialized_name: 'state',
                type: {
                  name: 'Enum',
                  module: 'JobPreparationTaskState'
                }
              },
              task_root_directory: {
                client_side_validation: true,
                required: false,
                serialized_name: 'taskRootDirectory',
                type: {
                  name: 'String'
                }
              },
              task_root_directory_url: {
                client_side_validation: true,
                required: false,
                serialized_name: 'taskRootDirectoryUrl',
                type: {
                  name: 'String'
                }
              },
              exit_code: {
                client_side_validation: true,
                required: false,
                serialized_name: 'exitCode',
                type: {
                  name: 'Number'
                }
              },
              container_info: {
                client_side_validation: true,
                required: false,
                serialized_name: 'containerInfo',
                type: {
                  name: 'Composite',
                  class_name: 'TaskContainerExecutionInformation'
                }
              },
              failure_info: {
                client_side_validation: true,
                required: false,
                serialized_name: 'failureInfo',
                type: {
                  name: 'Composite',
                  class_name: 'TaskFailureInformation'
                }
              },
              retry_count: {
                client_side_validation: true,
                required: true,
                serialized_name: 'retryCount',
                type: {
                  name: 'Number'
                }
              },
              last_retry_time: {
                client_side_validation: true,
                required: false,
                serialized_name: 'lastRetryTime',
                type: {
                  name: 'DateTime'
                }
              },
              result: {
                client_side_validation: true,
                required: false,
                serialized_name: 'result',
                type: {
                  name: 'Enum',
                  module: 'TaskExecutionResult'
                }
              }
            }
          }
        }
      end
    end
  end
end
