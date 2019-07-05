# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_03_01_6_1
  module Models
    #
    # The execution constraints for a job.
    #
    #
    class JobConstraints

      include MsRestAzure

      # @return [Duration] The maximum elapsed time that the job may run,
      # measured from the time the job is created. If the job does not complete
      # within the time limit, the Batch service terminates it and any tasks
      # that are still running. In this case, the termination reason will be
      # MaxWallClockTimeExpiry. If this property is not specified, there is no
      # time limit on how long the job may run.
      attr_accessor :max_wall_clock_time

      # @return [Integer] The maximum number of times each task may be retried.
      # The Batch service retries a task if its exit code is nonzero. Note that
      # this value specifically controls the number of retries. The Batch
      # service will try each task once, and may then retry up to this limit.
      # For example, if the maximum retry count is 3, Batch tries a task up to
      # 4 times (one initial try and 3 retries). If the maximum retry count is
      # 0, the Batch service does not retry tasks. If the maximum retry count
      # is -1, the Batch service retries tasks without limit. The default value
      # is 0 (no retries).
      attr_accessor :max_task_retry_count


      #
      # Mapper for JobConstraints class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'JobConstraints',
          type: {
            name: 'Composite',
            class_name: 'JobConstraints',
            model_properties: {
              max_wall_clock_time: {
                client_side_validation: true,
                required: false,
                serialized_name: 'maxWallClockTime',
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
