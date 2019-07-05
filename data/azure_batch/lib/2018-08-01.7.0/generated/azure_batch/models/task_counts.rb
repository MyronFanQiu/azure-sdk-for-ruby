# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_08_01_7_0
  module Models
    #
    # The task counts for a job.
    #
    #
    class TaskCounts

      include MsRestAzure

      # @return [Integer] The number of tasks in the active state.
      attr_accessor :active

      # @return [Integer] The number of tasks in the running or preparing
      # state.
      attr_accessor :running

      # @return [Integer] The number of tasks in the completed state.
      attr_accessor :completed

      # @return [Integer] The number of tasks which succeeded. A task succeeds
      # if its result (found in the executionInfo property) is 'success'.
      attr_accessor :succeeded

      # @return [Integer] The number of tasks which failed. A task fails if its
      # result (found in the executionInfo property) is 'failure'.
      attr_accessor :failed


      #
      # Mapper for TaskCounts class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'TaskCounts',
          type: {
            name: 'Composite',
            class_name: 'TaskCounts',
            model_properties: {
              active: {
                client_side_validation: true,
                required: true,
                serialized_name: 'active',
                type: {
                  name: 'Number'
                }
              },
              running: {
                client_side_validation: true,
                required: true,
                serialized_name: 'running',
                type: {
                  name: 'Number'
                }
              },
              completed: {
                client_side_validation: true,
                required: true,
                serialized_name: 'completed',
                type: {
                  name: 'Number'
                }
              },
              succeeded: {
                client_side_validation: true,
                required: true,
                serialized_name: 'succeeded',
                type: {
                  name: 'Number'
                }
              },
              failed: {
                client_side_validation: true,
                required: true,
                serialized_name: 'failed',
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
