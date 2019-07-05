# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_06_01_5_1
  module Models
    #
    # Represents a name-value pair.
    #
    #
    class NameValuePair

      include MsRestAzure

      # @return [String] The name in the name-value pair.
      attr_accessor :name

      # @return [String] The value in the name-value pair.
      attr_accessor :value


      #
      # Mapper for NameValuePair class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'NameValuePair',
          type: {
            name: 'Composite',
            class_name: 'NameValuePair',
            model_properties: {
              name: {
                client_side_validation: true,
                required: false,
                serialized_name: 'name',
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
