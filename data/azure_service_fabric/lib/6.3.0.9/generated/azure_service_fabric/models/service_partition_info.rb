# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::ServiceFabric::V6_3_0_9
  module Models
    #
    # Information about a partition of a Service Fabric service.
    #
    class ServicePartitionInfo

      include MsRestAzure

      @@discriminatorMap = Hash.new
      @@discriminatorMap["Stateful"] = "StatefulServicePartitionInfo"
      @@discriminatorMap["Stateless"] = "StatelessServicePartitionInfo"

      def initialize
        @ServiceKind = "ServicePartitionInfo"
      end

      attr_accessor :ServiceKind

      # @return [HealthState] The health state of a Service Fabric entity such
      # as Cluster, Node, Application, Service, Partition, Replica etc.
      # Possible values include: 'Invalid', 'Ok', 'Warning', 'Error', 'Unknown'
      attr_accessor :health_state

      # @return [ServicePartitionStatus] The status of the service fabric
      # service partition. Possible values include: 'Invalid', 'Ready',
      # 'NotReady', 'InQuorumLoss', 'Reconfiguring', 'Deleting'
      attr_accessor :partition_status

      # @return [PartitionInformation] Information about the partition
      # identity, partitioning scheme and keys supported by it.
      attr_accessor :partition_information


      #
      # Mapper for ServicePartitionInfo class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ServicePartitionInfo',
          type: {
            name: 'Composite',
            polymorphic_discriminator: 'ServiceKind',
            uber_parent: 'ServicePartitionInfo',
            class_name: 'ServicePartitionInfo',
            model_properties: {
              health_state: {
                client_side_validation: true,
                required: false,
                serialized_name: 'HealthState',
                type: {
                  name: 'String'
                }
              },
              partition_status: {
                client_side_validation: true,
                required: false,
                serialized_name: 'PartitionStatus',
                type: {
                  name: 'String'
                }
              },
              partition_information: {
                client_side_validation: true,
                required: false,
                serialized_name: 'PartitionInformation',
                type: {
                  name: 'Composite',
                  polymorphic_discriminator: 'ServicePartitionKind',
                  uber_parent: 'PartitionInformation',
                  class_name: 'PartitionInformation'
                }
              }
            }
          }
        }
      end
    end
  end
end
