# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_12_01_8_0
  module Models
    #
    # A collection of Azure Batch tasks to add.
    #
    #
    class TaskAddCollectionParameter

      include MsRestAzure

      # @return [Array<TaskAddParameter>] The collection of tasks to add. The
      # maximum count of tasks is 100. The total serialized size of this
      # collection must be less than 1MB. If it is greater than 1MB (for
      # example if each task has 100's of resource files or environment
      # variables), the request will fail with code 'RequestBodyTooLarge' and
      # should be retried again with fewer tasks.
      attr_accessor :value


      #
      # Mapper for TaskAddCollectionParameter class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'TaskAddCollectionParameter',
          type: {
            name: 'Composite',
            class_name: 'TaskAddCollectionParameter',
            model_properties: {
              value: {
                client_side_validation: true,
                required: true,
                serialized_name: 'value',
                constraints: {
                  MaxItems: 100
                },
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'TaskAddParameterElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'TaskAddParameter'
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
