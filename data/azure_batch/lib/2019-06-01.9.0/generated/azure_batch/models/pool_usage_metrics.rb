# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2019_06_01_9_0
  module Models
    #
    # Usage metrics for a Pool across an aggregation interval.
    #
    #
    class PoolUsageMetrics

      include MsRestAzure

      # @return [String] The ID of the Pool whose metrics are aggregated in
      # this entry.
      attr_accessor :pool_id

      # @return [DateTime] The start time of the aggregation interval covered
      # by this entry.
      attr_accessor :start_time

      # @return [DateTime] The end time of the aggregation interval covered by
      # this entry.
      attr_accessor :end_time

      # @return [String] The size of virtual machines in the Pool. All VMs in a
      # Pool are the same size. For information about available sizes of
      # virtual machines in Pools, see Choose a VM size for Compute Nodes in an
      # Azure Batch Pool
      # (https://docs.microsoft.com/azure/batch/batch-pool-vm-sizes).
      attr_accessor :vm_size

      # @return [Float] The total core hours used in the Pool during this
      # aggregation interval.
      attr_accessor :total_core_hours


      #
      # Mapper for PoolUsageMetrics class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'PoolUsageMetrics',
          type: {
            name: 'Composite',
            class_name: 'PoolUsageMetrics',
            model_properties: {
              pool_id: {
                client_side_validation: true,
                required: true,
                serialized_name: 'poolId',
                type: {
                  name: 'String'
                }
              },
              start_time: {
                client_side_validation: true,
                required: true,
                serialized_name: 'startTime',
                type: {
                  name: 'DateTime'
                }
              },
              end_time: {
                client_side_validation: true,
                required: true,
                serialized_name: 'endTime',
                type: {
                  name: 'DateTime'
                }
              },
              vm_size: {
                client_side_validation: true,
                required: true,
                serialized_name: 'vmSize',
                type: {
                  name: 'String'
                }
              },
              total_core_hours: {
                client_side_validation: true,
                required: true,
                serialized_name: 'totalCoreHours',
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