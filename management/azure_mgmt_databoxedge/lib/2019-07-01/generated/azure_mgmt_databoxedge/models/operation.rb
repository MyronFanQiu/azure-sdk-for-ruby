# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::DataBoxEdge::Mgmt::V2019_07_01
  module Models
    #
    # Operations.
    #
    class Operation

      include MsRestAzure

      # @return [String] Name of the operation.
      attr_accessor :name

      # @return [OperationDisplay] Properties displayed for the operation.
      attr_accessor :display

      # @return [String] Origin of the operation.
      attr_accessor :origin

      # @return [ServiceSpecification] Service specification.
      attr_accessor :service_specification


      #
      # Mapper for Operation class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'Operation',
          type: {
            name: 'Composite',
            class_name: 'Operation',
            model_properties: {
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
                  class_name: 'OperationDisplay'
                }
              },
              origin: {
                client_side_validation: true,
                required: false,
                serialized_name: 'origin',
                type: {
                  name: 'String'
                }
              },
              service_specification: {
                client_side_validation: true,
                required: false,
                serialized_name: 'properties.serviceSpecification',
                type: {
                  name: 'Composite',
                  class_name: 'ServiceSpecification'
                }
              }
            }
          }
        }
      end
    end
  end
end
