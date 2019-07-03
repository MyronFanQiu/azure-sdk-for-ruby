# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Hdinsight::Mgmt::V2018_06_01_preview
  module Models
    #
    # Gets the application HTTP endpoints.
    #
    class ApplicationGetHttpsEndpoint

      include MsRestAzure

      # @return [Array<String>] The list of access modes for the application.
      attr_accessor :access_modes

      # @return [String] The location of the endpoint.
      attr_accessor :location

      # @return [Integer] The destination port to connect to.
      attr_accessor :destination_port

      # @return [Integer] The public port to connect to.
      attr_accessor :public_port

      # @return [String] The subDomainSuffix of the application.
      attr_accessor :sub_domain_suffix

      # @return [Boolean] The value indicates whether to disable GatewayAuth.
      attr_accessor :disable_gateway_auth


      #
      # Mapper for ApplicationGetHttpsEndpoint class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ApplicationGetHttpsEndpoint',
          type: {
            name: 'Composite',
            class_name: 'ApplicationGetHttpsEndpoint',
            model_properties: {
              access_modes: {
                client_side_validation: true,
                required: false,
                serialized_name: 'accessModes',
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
              location: {
                client_side_validation: true,
                required: false,
                serialized_name: 'location',
                type: {
                  name: 'String'
                }
              },
              destination_port: {
                client_side_validation: true,
                required: false,
                serialized_name: 'destinationPort',
                type: {
                  name: 'Number'
                }
              },
              public_port: {
                client_side_validation: true,
                required: false,
                serialized_name: 'publicPort',
                type: {
                  name: 'Number'
                }
              },
              sub_domain_suffix: {
                client_side_validation: true,
                required: false,
                serialized_name: 'subDomainSuffix',
                type: {
                  name: 'String'
                }
              },
              disable_gateway_auth: {
                client_side_validation: true,
                required: false,
                serialized_name: 'disableGatewayAuth',
                type: {
                  name: 'Boolean'
                }
              }
            }
          }
        }
      end
    end
  end
end
