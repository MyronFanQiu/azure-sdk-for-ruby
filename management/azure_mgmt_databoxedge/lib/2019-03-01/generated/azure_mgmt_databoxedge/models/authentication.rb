# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::DataBoxEdge::Mgmt::V2019_03_01
  module Models
    #
    # Authentication mechanism for IoT devices.
    #
    class Authentication

      include MsRestAzure

      # @return [SymmetricKey] Symmetric key for authentication.
      attr_accessor :symmetric_key


      #
      # Mapper for Authentication class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'Authentication',
          type: {
            name: 'Composite',
            class_name: 'Authentication',
            model_properties: {
              symmetric_key: {
                client_side_validation: true,
                required: false,
                serialized_name: 'symmetricKey',
                type: {
                  name: 'Composite',
                  class_name: 'SymmetricKey'
                }
              }
            }
          }
        }
      end
    end
  end
end
