# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::CostManagement::Mgmt::V2019_03_01_preview
  module Models
    #
    # The list of ExternalSubscriptionIds operation request.
    #
    class ExternalSubscriptionIdListRequest

      include MsRestAzure

      # @return [Array<String>] The list of ExternalSubscriptionIds.
      attr_accessor :value


      #
      # Mapper for ExternalSubscriptionIdListRequest class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ExternalSubscriptionIdListRequest',
          type: {
            name: 'Composite',
            class_name: 'ExternalSubscriptionIdListRequest',
            model_properties: {
              value: {
                client_side_validation: true,
                required: false,
                serialized_name: 'value',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'StringElementType',
                      type: {
                        name: 'String'
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