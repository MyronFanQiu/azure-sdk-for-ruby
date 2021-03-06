# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Compute::Mgmt::V2019_07_01
  module Models
    #
    # The List Compute Operation operation response.
    #
    class ComputeOperationListResult

      include MsRestAzure

      # @return [Array<ComputeOperationValue>] The list of compute operations
      attr_accessor :value


      #
      # Mapper for ComputeOperationListResult class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ComputeOperationListResult',
          type: {
            name: 'Composite',
            class_name: 'ComputeOperationListResult',
            model_properties: {
              value: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'value',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'ComputeOperationValueElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'ComputeOperationValue'
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
