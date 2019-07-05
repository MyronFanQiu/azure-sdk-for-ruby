# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2019_06_01_9_0
  module Models
    #
    # Information about a file or directory on a Compute Node.
    #
    #
    class NodeFile

      include MsRestAzure

      # @return [String] The file path.
      attr_accessor :name

      # @return [String] The URL of the file.
      attr_accessor :url

      # @return [Boolean] Whether the object represents a directory.
      attr_accessor :is_directory

      # @return [FileProperties] The file properties.
      attr_accessor :properties


      #
      # Mapper for NodeFile class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'NodeFile',
          type: {
            name: 'Composite',
            class_name: 'NodeFile',
            model_properties: {
              name: {
                client_side_validation: true,
                required: false,
                serialized_name: 'name',
                type: {
                  name: 'String'
                }
              },
              url: {
                client_side_validation: true,
                required: false,
                serialized_name: 'url',
                type: {
                  name: 'String'
                }
              },
              is_directory: {
                client_side_validation: true,
                required: false,
                serialized_name: 'isDirectory',
                type: {
                  name: 'Boolean'
                }
              },
              properties: {
                client_side_validation: true,
                required: false,
                serialized_name: 'properties',
                type: {
                  name: 'Composite',
                  class_name: 'FileProperties'
                }
              }
            }
          }
        }
      end
    end
  end
end
