# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::CognitiveServices::Qnamaker::V4_0
  module Models
    #
    # Name - value pair of metadata.
    #
    class MetadataDTO

      include MsRestAzure

      # @return [String] Metadata name.
      attr_accessor :name

      # @return [String] Metadata value.
      attr_accessor :value


      #
      # Mapper for MetadataDTO class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          required: false,
          serialized_name: 'MetadataDTO',
          type: {
            name: 'Composite',
            class_name: 'MetadataDTO',
            model_properties: {
              name: {
                required: true,
                serialized_name: 'name',
                constraints: {
                  MaxLength: 100,
                  MinLength: 1
                },
                type: {
                  name: 'String'
                }
              },
              value: {
                required: true,
                serialized_name: 'value',
                constraints: {
                  MaxLength: 500,
                  MinLength: 1
                },
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
