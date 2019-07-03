# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::ContainerRegistry::Mgmt::V2019_05_01
  module Models
    #
    # Virtual network rule.
    #
    class VirtualNetworkRule

      include MsRestAzure

      # @return [Action] The action of virtual network rule. Possible values
      # include: 'Allow'. Default value: 'Allow' .
      attr_accessor :action

      # @return [String] Resource ID of a subnet, for example:
      # /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/virtualNetworks/{vnetName}/subnets/{subnetName}.
      attr_accessor :virtual_network_resource_id


      #
      # Mapper for VirtualNetworkRule class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'VirtualNetworkRule',
          type: {
            name: 'Composite',
            class_name: 'VirtualNetworkRule',
            model_properties: {
              action: {
                client_side_validation: true,
                required: false,
                serialized_name: 'action',
                default_value: 'Allow',
                type: {
                  name: 'String'
                }
              },
              virtual_network_resource_id: {
                client_side_validation: true,
                required: true,
                serialized_name: 'id',
                type: {
                  name: 'String'
                }
              }
            }
          }
        }
      end
    end
  end
end
