# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::ContainerRegistry::Mgmt::V2019_05_01
  module Models
    #
    # The definition of a container registry operation.
    #
    class OperationDefinition

      include MsRestAzure

      # @return [String] The origin information of the container registry
      # operation.
      attr_accessor :origin

      # @return [String] Operation name: {provider}/{resource}/{operation}.
      attr_accessor :name

      # @return [OperationDisplayDefinition] The display information for the
      # container registry operation.
      attr_accessor :display

      # @return [OperationServiceSpecificationDefinition] The definition of
      # Azure Monitoring service.
      attr_accessor :service_specification


      #
      # Mapper for OperationDefinition class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'OperationDefinition',
          type: {
            name: 'Composite',
            class_name: 'OperationDefinition',
            model_properties: {
              origin: {
                client_side_validation: true,
                required: false,
                serialized_name: 'origin',
                type: {
                  name: 'String'
                }
              },
              name: {
                client_side_validation: true,
                required: false,
                serialized_name: 'name',
                type: {
                  name: 'String'
                }
              },
              display: {
                client_side_validation: true,
                required: false,
                serialized_name: 'display',
                type: {
                  name: 'Composite',
                  class_name: 'OperationDisplayDefinition'
                }
              },
              service_specification: {
                client_side_validation: true,
                required: false,
                serialized_name: 'properties.serviceSpecification',
                type: {
                  name: 'Composite',
                  class_name: 'OperationServiceSpecificationDefinition'
                }
              }
            }
          }
        }
      end
    end
  end
end
