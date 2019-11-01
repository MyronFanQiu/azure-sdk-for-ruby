# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Network::Mgmt::V2019_09_01
  module Models
    #
    # Route Filter Rule Resource.
    #
    class PatchRouteFilterRule < SubResource

      include MsRestAzure

      # @return [Access] The access type of the rule. Possible values include:
      # 'Allow', 'Deny'
      attr_accessor :access

      # @return [String] The rule type of the rule. Default value: 'Community'
      # .
      attr_accessor :route_filter_rule_type

      # @return [Array<String>] The collection for bgp community values to
      # filter on. e.g. ['12076:5010','12076:5020'].
      attr_accessor :communities

      # @return [ProvisioningState] The provisioning state of the route filter
      # rule resource. Possible values include: 'Succeeded', 'Updating',
      # 'Deleting', 'Failed'
      attr_accessor :provisioning_state

      # @return [String] The name of the resource that is unique within a
      # resource group. This name can be used to access the resource.
      attr_accessor :name

      # @return [String] A unique read-only string that changes whenever the
      # resource is updated.
      attr_accessor :etag


      #
      # Mapper for PatchRouteFilterRule class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'PatchRouteFilterRule',
          type: {
            name: 'Composite',
            class_name: 'PatchRouteFilterRule',
            model_properties: {
              id: {
                client_side_validation: true,
                required: false,
                serialized_name: 'id',
                type: {
                  name: 'String'
                }
              },
              access: {
                client_side_validation: true,
                required: true,
                serialized_name: 'properties.access',
                type: {
                  name: 'String'
                }
              },
              route_filter_rule_type: {
                client_side_validation: true,
                required: true,
                is_constant: true,
                serialized_name: 'properties.routeFilterRuleType',
                default_value: 'Community',
                type: {
                  name: 'String'
                }
              },
              communities: {
                client_side_validation: true,
                required: true,
                serialized_name: 'properties.communities',
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
              },
              provisioning_state: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'properties.provisioningState',
                type: {
                  name: 'String'
                }
              },
              name: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'name',
                type: {
                  name: 'String'
                }
              },
              etag: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'etag',
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
