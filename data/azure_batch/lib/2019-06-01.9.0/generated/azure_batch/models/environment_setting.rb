# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2019_06_01_9_0
  module Models
    #
    # An environment variable to be set on a Task process.
    #
    #
    class EnvironmentSetting

      include MsRestAzure

      # @return [String] The name of the environment variable.
      attr_accessor :name

      # @return [String] The value of the environment variable.
      attr_accessor :value


      #
      # Mapper for EnvironmentSetting class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'EnvironmentSetting',
          type: {
            name: 'Composite',
            class_name: 'EnvironmentSetting',
            model_properties: {
              name: {
                client_side_validation: true,
                required: true,
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
