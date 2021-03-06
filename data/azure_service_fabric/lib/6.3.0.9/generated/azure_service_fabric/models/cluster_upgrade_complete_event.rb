# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::ServiceFabric::V6_3_0_9
  module Models
    #
    # Cluster Upgrade Complete event.
    #
    class ClusterUpgradeCompleteEvent < ClusterEvent

      include MsRestAzure


      def initialize
        @Kind = "ClusterUpgradeComplete"
      end

      attr_accessor :Kind

      # @return [String] Target Cluster version.
      attr_accessor :target_cluster_version

      # @return [Float] Overall duration of upgrade in milli-seconds.
      attr_accessor :overall_upgrade_elapsed_time_in_ms


      #
      # Mapper for ClusterUpgradeCompleteEvent class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ClusterUpgradeComplete',
          type: {
            name: 'Composite',
            class_name: 'ClusterUpgradeCompleteEvent',
            model_properties: {
              event_instance_id: {
                client_side_validation: true,
                required: true,
                serialized_name: 'EventInstanceId',
                type: {
                  name: 'String'
                }
              },
              time_stamp: {
                client_side_validation: true,
                required: true,
                serialized_name: 'TimeStamp',
                type: {
                  name: 'DateTime'
                }
              },
              has_correlated_events: {
                client_side_validation: true,
                required: false,
                serialized_name: 'HasCorrelatedEvents',
                type: {
                  name: 'Boolean'
                }
              },
              Kind: {
                client_side_validation: true,
                required: true,
                serialized_name: 'Kind',
                type: {
                  name: 'String'
                }
              },
              target_cluster_version: {
                client_side_validation: true,
                required: false,
                serialized_name: 'TargetClusterVersion',
                type: {
                  name: 'String'
                }
              },
              overall_upgrade_elapsed_time_in_ms: {
                client_side_validation: true,
                required: false,
                serialized_name: 'OverallUpgradeElapsedTimeInMs',
                type: {
                  name: 'Double'
                }
              }
            }
          }
        }
      end
    end
  end
end
