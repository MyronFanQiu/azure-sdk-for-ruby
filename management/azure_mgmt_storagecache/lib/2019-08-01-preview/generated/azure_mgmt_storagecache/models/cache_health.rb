# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::StorageCache::Mgmt::V2019_08_01_preview
  module Models
    #
    # An indication of cache health.  Gives more information about health than
    # just that related to provisioning.
    #
    class CacheHealth

      include MsRestAzure

      # @return [HealthStateType] List of cache health states. Possible values
      # include: 'Unknown', 'Healthy', 'Degraded', 'Down', 'Transitioning',
      # 'Stopping', 'Stopped', 'Upgrading', 'Flushing'
      attr_accessor :state

      # @return [String] Describes explanation of state.
      attr_accessor :status_description


      #
      # Mapper for CacheHealth class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'CacheHealth',
          type: {
            name: 'Composite',
            class_name: 'CacheHealth',
            model_properties: {
              state: {
                client_side_validation: true,
                required: false,
                serialized_name: 'state',
                type: {
                  name: 'String'
                }
              },
              status_description: {
                client_side_validation: true,
                required: false,
                serialized_name: 'statusDescription',
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
