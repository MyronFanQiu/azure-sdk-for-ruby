# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_03_01_6_1
  module Models
    #
    # An error message received in an Azure Batch error response.
    #
    #
    class ErrorMessage

      include MsRestAzure

      # @return [String] The language code of the error message.
      attr_accessor :lang

      # @return [String] The text of the message.
      attr_accessor :value


      #
      # Mapper for ErrorMessage class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ErrorMessage',
          type: {
            name: 'Composite',
            class_name: 'ErrorMessage',
            model_properties: {
              lang: {
                client_side_validation: true,
                required: false,
                serialized_name: 'lang',
                type: {
                  name: 'String'
                }
              },
              value: {
                client_side_validation: true,
                required: false,
                serialized_name: 'value',
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
