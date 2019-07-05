# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_12_01_8_0
  module Models
    #
    # Statistics related to resource consumption by compute nodes in a pool.
    #
    #
    class ResourceStatistics

      include MsRestAzure

      # @return [DateTime] The start time of the time range covered by the
      # statistics.
      attr_accessor :start_time

      # @return [DateTime] The time at which the statistics were last updated.
      # All statistics are limited to the range between startTime and
      # lastUpdateTime.
      attr_accessor :last_update_time

      # @return [Float] The average CPU usage across all nodes in the pool
      # (percentage per node).
      attr_accessor :avg_cpupercentage

      # @return [Float] The average memory usage in GiB across all nodes in the
      # pool.
      attr_accessor :avg_memory_gi_b

      # @return [Float] The peak memory usage in GiB across all nodes in the
      # pool.
      attr_accessor :peak_memory_gi_b

      # @return [Float] The average used disk space in GiB across all nodes in
      # the pool.
      attr_accessor :avg_disk_gi_b

      # @return [Float] The peak used disk space in GiB across all nodes in the
      # pool.
      attr_accessor :peak_disk_gi_b

      # @return [Integer] The total number of disk read operations across all
      # nodes in the pool.
      attr_accessor :disk_read_iops

      # @return [Integer] The total number of disk write operations across all
      # nodes in the pool.
      attr_accessor :disk_write_iops

      # @return [Float] The total amount of data in GiB of disk reads across
      # all nodes in the pool.
      attr_accessor :disk_read_gi_b

      # @return [Float] The total amount of data in GiB of disk writes across
      # all nodes in the pool.
      attr_accessor :disk_write_gi_b

      # @return [Float] The total amount of data in GiB of network reads across
      # all nodes in the pool.
      attr_accessor :network_read_gi_b

      # @return [Float] The total amount of data in GiB of network writes
      # across all nodes in the pool.
      attr_accessor :network_write_gi_b


      #
      # Mapper for ResourceStatistics class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ResourceStatistics',
          type: {
            name: 'Composite',
            class_name: 'ResourceStatistics',
            model_properties: {
              start_time: {
                client_side_validation: true,
                required: true,
                serialized_name: 'startTime',
                type: {
                  name: 'DateTime'
                }
              },
              last_update_time: {
                client_side_validation: true,
                required: true,
                serialized_name: 'lastUpdateTime',
                type: {
                  name: 'DateTime'
                }
              },
              avg_cpupercentage: {
                client_side_validation: true,
                required: true,
                serialized_name: 'avgCPUPercentage',
                type: {
                  name: 'Double'
                }
              },
              avg_memory_gi_b: {
                client_side_validation: true,
                required: true,
                serialized_name: 'avgMemoryGiB',
                type: {
                  name: 'Double'
                }
              },
              peak_memory_gi_b: {
                client_side_validation: true,
                required: true,
                serialized_name: 'peakMemoryGiB',
                type: {
                  name: 'Double'
                }
              },
              avg_disk_gi_b: {
                client_side_validation: true,
                required: true,
                serialized_name: 'avgDiskGiB',
                type: {
                  name: 'Double'
                }
              },
              peak_disk_gi_b: {
                client_side_validation: true,
                required: true,
                serialized_name: 'peakDiskGiB',
                type: {
                  name: 'Double'
                }
              },
              disk_read_iops: {
                client_side_validation: true,
                required: true,
                serialized_name: 'diskReadIOps',
                type: {
                  name: 'Number'
                }
              },
              disk_write_iops: {
                client_side_validation: true,
                required: true,
                serialized_name: 'diskWriteIOps',
                type: {
                  name: 'Number'
                }
              },
              disk_read_gi_b: {
                client_side_validation: true,
                required: true,
                serialized_name: 'diskReadGiB',
                type: {
                  name: 'Double'
                }
              },
              disk_write_gi_b: {
                client_side_validation: true,
                required: true,
                serialized_name: 'diskWriteGiB',
                type: {
                  name: 'Double'
                }
              },
              network_read_gi_b: {
                client_side_validation: true,
                required: true,
                serialized_name: 'networkReadGiB',
                type: {
                  name: 'Double'
                }
              },
              network_write_gi_b: {
                client_side_validation: true,
                required: true,
                serialized_name: 'networkWriteGiB',
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
