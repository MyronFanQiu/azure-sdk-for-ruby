# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::ServiceFabric::V6_5_0_36
  module Models
    #
    # Information about a stateless Service Fabric service.
    #
    class StatelessServiceInfo < ServiceInfo

      include MsRestAzure


      def initialize
        @ServiceKind = "Stateless"
      end

      attr_accessor :ServiceKind


      #
      # Mapper for StatelessServiceInfo class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'Stateless',
          type: {
            name: 'Composite',
            class_name: 'StatelessServiceInfo',
            model_properties: {
              id: {
                client_side_validation: true,
                required: false,
                serialized_name: 'Id',
                type: {
                  name: 'String'
                }
              },
              name: {
                client_side_validation: true,
                required: false,
                serialized_name: 'Name',
                type: {
                  name: 'String'
                }
              },
              type_name: {
                client_side_validation: true,
                required: false,
                serialized_name: 'TypeName',
                type: {
                  name: 'String'
                }
              },
              manifest_version: {
                client_side_validation: true,
                required: false,
                serialized_name: 'ManifestVersion',
                type: {
                  name: 'String'
                }
              },
              health_state: {
                client_side_validation: true,
                required: false,
                serialized_name: 'HealthState',
                type: {
                  name: 'String'
                }
              },
              service_status: {
                client_side_validation: true,
                required: false,
                serialized_name: 'ServiceStatus',
                type: {
                  name: 'String'
                }
              },
              is_service_group: {
                client_side_validation: true,
                required: false,
                serialized_name: 'IsServiceGroup',
                type: {
                  name: 'Boolean'
                }
              },
              ServiceKind: {
                client_side_validation: true,
                required: true,
                serialized_name: 'ServiceKind',
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
