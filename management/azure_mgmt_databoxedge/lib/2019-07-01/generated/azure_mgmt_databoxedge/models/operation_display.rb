# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::DataBoxEdge::Mgmt::V2019_07_01
  module Models
    #
    # Operation display properties.
    #
    class OperationDisplay

      include MsRestAzure

      # @return [String] Provider name.
      attr_accessor :provider

      # @return [String] The type of resource in which the operation is
      # performed.
      attr_accessor :resource

      # @return [String] Operation to be performed on the resource.
      attr_accessor :operation

      # @return [String] Description of the operation to be performed.
      attr_accessor :description


      #
      # Mapper for OperationDisplay class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'OperationDisplay',
          type: {
            name: 'Composite',
            class_name: 'OperationDisplay',
            model_properties: {
              provider: {
                client_side_validation: true,
                required: false,
                serialized_name: 'provider',
                type: {
                  name: 'String'
                }
              },
              resource: {
                client_side_validation: true,
                required: false,
                serialized_name: 'resource',
                type: {
                  name: 'String'
                }
              },
              operation: {
                client_side_validation: true,
                required: false,
                serialized_name: 'operation',
                type: {
                  name: 'String'
                }
              },
              description: {
                client_side_validation: true,
                required: false,
                serialized_name: 'description',
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
