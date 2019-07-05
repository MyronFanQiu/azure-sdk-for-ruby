# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_09_01_6_0
  module Models
    #
    # Information about the compute node on which a task ran.
    #
    #
    class ComputeNodeInformation

      include MsRestAzure

      # @return [String] An identifier for the compute node on which the task
      # ran, which can be passed when adding a task to request that the task be
      # scheduled on this compute node.
      attr_accessor :affinity_id

      # @return [String] The URL of the node on which the task ran. .
      attr_accessor :node_url

      # @return [String] The ID of the pool on which the task ran.
      attr_accessor :pool_id

      # @return [String] The ID of the node on which the task ran.
      attr_accessor :node_id

      # @return [String] The root directory of the task on the compute node.
      attr_accessor :task_root_directory

      # @return [String] The URL to the root directory of the task on the
      # compute node.
      attr_accessor :task_root_directory_url


      #
      # Mapper for ComputeNodeInformation class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ComputeNodeInformation',
          type: {
            name: 'Composite',
            class_name: 'ComputeNodeInformation',
            model_properties: {
              affinity_id: {
                client_side_validation: true,
                required: false,
                serialized_name: 'affinityId',
                type: {
                  name: 'String'
                }
              },
              node_url: {
                client_side_validation: true,
                required: false,
                serialized_name: 'nodeUrl',
                type: {
                  name: 'String'
                }
              },
              pool_id: {
                client_side_validation: true,
                required: false,
                serialized_name: 'poolId',
                type: {
                  name: 'String'
                }
              },
              node_id: {
                client_side_validation: true,
                required: false,
                serialized_name: 'nodeId',
                type: {
                  name: 'String'
                }
              },
              task_root_directory: {
                client_side_validation: true,
                required: false,
                serialized_name: 'taskRootDirectory',
                type: {
                  name: 'String'
                }
              },
              task_root_directory_url: {
                client_side_validation: true,
                required: false,
                serialized_name: 'taskRootDirectoryUrl',
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
