# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_09_01_6_0
  module Models
    #
    # A inbound NAT pool that can be used to address specific ports on compute
    # nodes in a Batch pool externally.
    #
    #
    class InboundNATPool

      include MsRestAzure

      # @return [String] The name of the endpoint. The name must be unique
      # within a Batch pool, can contain letters, numbers, underscores,
      # periods, and hyphens. Names must start with a letter or number, must
      # end with a letter, number, or underscore, and cannot exceed 77
      # characters.  If any invalid values are provided the request fails with
      # HTTP status code 400.
      attr_accessor :name

      # @return [InboundEndpointProtocol] The protocol of the endpoint.
      # Possible values include: 'tcp', 'udp'
      attr_accessor :protocol

      # @return [Integer] The port number on the compute node. This must be
      # unique within a Batch pool. Acceptable values are between 1 and 65535
      # except for 22, 3389, 29876 and 29877 as these are reserved. If any
      # reserved values are provided the request fails with HTTP status code
      # 400.
      attr_accessor :backend_port

      # @return [Integer] The first port number in the range of external ports
      # that will be used to provide inbound access to the backendPort on
      # individual compute nodes. Acceptable values range between 1 and 65534
      # except ports from 50000 to 55000 which are reserved. All ranges within
      # a pool must be distinct and cannot overlap. Each range must contain at
      # least 40 ports. If any reserved or overlapping values are provided the
      # request fails with HTTP status code 400.
      attr_accessor :frontend_port_range_start

      # @return [Integer] The last port number in the range of external ports
      # that will be used to provide inbound access to the backendPort on
      # individual compute nodes. Acceptable values range between 1 and 65534
      # except ports from 50000 to 55000 which are reserved by the Batch
      # service. All ranges within a pool must be distinct and cannot overlap.
      # Each range must contain at least 40 ports. If any reserved or
      # overlapping values are provided the request fails with HTTP status code
      # 400.
      attr_accessor :frontend_port_range_end

      # @return [Array<NetworkSecurityGroupRule>] A list of network security
      # group rules that will be applied to the endpoint. The maximum number of
      # rules that can be specified across all the endpoints on a Batch pool is
      # 25. If no network security group rules are specified, a default rule
      # will be created to allow inbound access to the specified backendPort.
      # If the maximum number of network security group rules is exceeded the
      # request fails with HTTP status code 400.
      attr_accessor :network_security_group_rules


      #
      # Mapper for InboundNATPool class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'InboundNATPool',
          type: {
            name: 'Composite',
            class_name: 'InboundNATPool',
            model_properties: {
              name: {
                client_side_validation: true,
                required: true,
                serialized_name: 'name',
                type: {
                  name: 'String'
                }
              },
              protocol: {
                client_side_validation: true,
                required: true,
                serialized_name: 'protocol',
                type: {
                  name: 'Enum',
                  module: 'InboundEndpointProtocol'
                }
              },
              backend_port: {
                client_side_validation: true,
                required: true,
                serialized_name: 'backendPort',
                type: {
                  name: 'Number'
                }
              },
              frontend_port_range_start: {
                client_side_validation: true,
                required: true,
                serialized_name: 'frontendPortRangeStart',
                type: {
                  name: 'Number'
                }
              },
              frontend_port_range_end: {
                client_side_validation: true,
                required: true,
                serialized_name: 'frontendPortRangeEnd',
                type: {
                  name: 'Number'
                }
              },
              network_security_group_rules: {
                client_side_validation: true,
                required: false,
                serialized_name: 'networkSecurityGroupRules',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'NetworkSecurityGroupRuleElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'NetworkSecurityGroupRule'
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
