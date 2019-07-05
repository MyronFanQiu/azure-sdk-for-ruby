# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_03_01_6_1
  module Models
    #
    # Options for upgrading the operating system of compute nodes in a pool.
    #
    #
    class PoolUpgradeOSParameter

      include MsRestAzure

      # @return [String] The Azure Guest OS version to be installed on the
      # virtual machines in the pool.
      attr_accessor :target_osversion


      #
      # Mapper for PoolUpgradeOSParameter class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'PoolUpgradeOSParameter',
          type: {
            name: 'Composite',
            class_name: 'PoolUpgradeOSParameter',
            model_properties: {
              target_osversion: {
                client_side_validation: true,
                required: true,
                serialized_name: 'targetOSVersion',
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
