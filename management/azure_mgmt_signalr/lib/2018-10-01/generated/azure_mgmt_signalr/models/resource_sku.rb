# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Signalr::Mgmt::V2018_10_01
  module Models
    #
    # The billing information of the SignalR resource.
    #
    class ResourceSku

      include MsRestAzure

      # @return [String] The name of the SKU. Required.
      #
      # Allowed values: Standard_S1, Free_F1
      attr_accessor :name

      # @return [SignalRSkuTier] Optional tier of this particular SKU.
      # 'Standard' or 'Free'.
      #
      # `Basic` is deprecated, use `Standard` instead. Possible values include:
      # 'Free', 'Basic', 'Standard', 'Premium'
      attr_accessor :tier

      # @return [String] Optional string. For future use.
      attr_accessor :size

      # @return [String] Optional string. For future use.
      attr_accessor :family

      # @return [Integer] Optional, integer. The unit count of SignalR
      # resource. 1 by default.
      #
      # If present, following values are allowed:
      # Free: 1
      # Standard: 1,2,5,10,20,50,100
      attr_accessor :capacity


      #
      # Mapper for ResourceSku class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ResourceSku',
          type: {
            name: 'Composite',
            class_name: 'ResourceSku',
            model_properties: {
              name: {
                client_side_validation: true,
                required: true,
                serialized_name: 'name',
                type: {
                  name: 'String'
                }
              },
              tier: {
                client_side_validation: true,
                required: false,
                serialized_name: 'tier',
                type: {
                  name: 'String'
                }
              },
              size: {
                client_side_validation: true,
                required: false,
                serialized_name: 'size',
                type: {
                  name: 'String'
                }
              },
              family: {
                client_side_validation: true,
                required: false,
                serialized_name: 'family',
                type: {
                  name: 'String'
                }
              },
              capacity: {
                client_side_validation: true,
                required: false,
                serialized_name: 'capacity',
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
