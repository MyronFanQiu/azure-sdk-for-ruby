# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_06_01_5_1
  module Models
    #
    # A network security group rule to apply to an inbound endpoint.
    #
    #
    class NetworkSecurityGroupRule

      include MsRestAzure

      # @return [Integer] The priority for this rule. Priorities within a pool
      # must be unique and are evaluated in order of priority. The lower the
      # number the higher the priority. For example, rules could be specified
      # with order numbers of 150, 250, and 350. The rule with the order number
      # of 150 takes precedence over the rule that has an order of 250. Allowed
      # priorities are 150 to 3500. If any reserved or duplicate values are
      # provided the request fails with HTTP status code 400.
      attr_accessor :priority

      # @return [NetworkSecurityGroupRuleAccess] The action that should be
      # taken for a specified IP address, subnet range or tag. Possible values
      # include: 'allow', 'deny'
      attr_accessor :access

      # @return [String] The source address prefix or tag to match for the
      # rule. Valid values are a single IP address (i.e. 10.10.10.10), IP
      # subnet (i.e. 192.168.1.0/24), default tag, or * (for all addresses).
      # If any other values are provided the request fails with HTTP status
      # code 400.
      attr_accessor :source_address_prefix


      #
      # Mapper for NetworkSecurityGroupRule class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'NetworkSecurityGroupRule',
          type: {
            name: 'Composite',
            class_name: 'NetworkSecurityGroupRule',
            model_properties: {
              priority: {
                client_side_validation: true,
                required: true,
                serialized_name: 'priority',
                type: {
                  name: 'Number'
                }
              },
              access: {
                client_side_validation: true,
                required: true,
                serialized_name: 'access',
                type: {
                  name: 'Enum',
                  module: 'NetworkSecurityGroupRuleAccess'
                }
              },
              source_address_prefix: {
                client_side_validation: true,
                required: true,
                serialized_name: 'sourceAddressPrefix',
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
