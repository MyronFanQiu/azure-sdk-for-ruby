# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_06_01_5_1
  module Models
    #
    # Execution constraints to apply to a task.
    #
    #
    class TaskConstraints

      include MsRestAzure

      # @return [Duration] The maximum elapsed time that the task may run,
      # measured from the time the task starts. If the task does not complete
      # within the time limit, the Batch service terminates it. If this is not
      # specified, there is no time limit on how long the task may run.
      attr_accessor :max_wall_clock_time

      # @return [Duration] The minimum time to retain the task directory on the
      # compute node where it ran, from the time it completes execution. After
      # this time, the Batch service may delete the task directory and all its
      # contents. The default is infinite, i.e. the task directory will be
      # retained until the compute node is removed or reimaged.
      attr_accessor :retention_time

      # @return [Integer] The maximum number of times the task may be retried.
      # The Batch service retries a task if its exit code is nonzero. Note that
      # this value specifically controls the number of retries. The Batch
      # service will try the task once, and may then retry up to this limit.
      # For example, if the maximum retry count is 3, Batch tries the task up
      # to 4 times (one initial try and 3 retries). If the maximum retry count
      # is 0, the Batch service does not retry the task. If the maximum retry
      # count is -1, the Batch service retries the task without limit.
      attr_accessor :max_task_retry_count


      #
      # Mapper for TaskConstraints class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'TaskConstraints',
          type: {
            name: 'Composite',
            class_name: 'TaskConstraints',
            model_properties: {
              max_wall_clock_time: {
                client_side_validation: true,
                required: false,
                serialized_name: 'maxWallClockTime',
                type: {
                  name: 'TimeSpan'
                }
              },
              retention_time: {
                client_side_validation: true,
                required: false,
                serialized_name: 'retentionTime',
                type: {
                  name: 'TimeSpan'
                }
              },
              max_task_retry_count: {
                client_side_validation: true,
                required: false,
                serialized_name: 'maxTaskRetryCount',
                type: {
                  name: 'Number'
                }
              }
            }
          }
        }
      end
    end
  end
end
