# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::ARM::ContainerRegistry::Api_2017_06_01_preview
  module Models
    #
    # The properties of a storage account for a container registry. Only
    # applicable to Basic SKU.
    #
    class StorageAccountProperties

      include MsRestAzure

      include MsRest::JSONable
      # @return [String] The resource ID of the storage account.
      attr_accessor :id


      #
      # Mapper for StorageAccountProperties class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          required: false,
          serialized_name: 'StorageAccountProperties',
          type: {
            name: 'Composite',
            class_name: 'StorageAccountProperties',
            model_properties: {
              id: {
                required: true,
                serialized_name: 'id',
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