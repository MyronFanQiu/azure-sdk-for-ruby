# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::DataBoxEdge::Mgmt::V2019_07_01
  module Models
    #
    # Details related to the IPv6 address configuration.
    #
    class Ipv6Config

      include MsRestAzure

      # @return [String] The IPv6 address of the network adapter.
      attr_accessor :ip_address

      # @return [Integer] The IPv6 prefix of the network adapter.
      attr_accessor :prefix_length

      # @return [String] The IPv6 gateway of the network adapter.
      attr_accessor :gateway


      #
      # Mapper for Ipv6Config class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'Ipv6Config',
          type: {
            name: 'Composite',
            class_name: 'Ipv6Config',
            model_properties: {
              ip_address: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'ipAddress',
                type: {
                  name: 'String'
                }
              },
              prefix_length: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'prefixLength',
                type: {
                  name: 'Number'
                }
              },
              gateway: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'gateway',
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
