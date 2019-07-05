# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_08_01_7_0
  module Models
    #
    # The status of the Job Preparation and Job Release tasks on a compute
    # node.
    #
    #
    class JobPreparationAndReleaseTaskExecutionInformation

      include MsRestAzure

      # @return [String] The ID of the pool containing the compute node to
      # which this entry refers.
      attr_accessor :pool_id

      # @return [String] The ID of the compute node to which this entry refers.
      attr_accessor :node_id

      # @return [String] The URL of the compute node to which this entry
      # refers.
      attr_accessor :node_url

      # @return [JobPreparationTaskExecutionInformation] Information about the
      # execution status of the Job Preparation task on this compute node.
      attr_accessor :job_preparation_task_execution_info

      # @return [JobReleaseTaskExecutionInformation] Information about the
      # execution status of the Job Release task on this compute node. This
      # property is set only if the Job Release task has run on the node.
      attr_accessor :job_release_task_execution_info


      #
      # Mapper for JobPreparationAndReleaseTaskExecutionInformation class as
      # Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'JobPreparationAndReleaseTaskExecutionInformation',
          type: {
            name: 'Composite',
            class_name: 'JobPreparationAndReleaseTaskExecutionInformation',
            model_properties: {
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
              node_url: {
                client_side_validation: true,
                required: false,
                serialized_name: 'nodeUrl',
                type: {
                  name: 'String'
                }
              },
              job_preparation_task_execution_info: {
                client_side_validation: true,
                required: false,
                serialized_name: 'jobPreparationTaskExecutionInfo',
                type: {
                  name: 'Composite',
                  class_name: 'JobPreparationTaskExecutionInformation'
                }
              },
              job_release_task_execution_info: {
                client_side_validation: true,
                required: false,
                serialized_name: 'jobReleaseTaskExecutionInfo',
                type: {
                  name: 'Composite',
                  class_name: 'JobReleaseTaskExecutionInformation'
                }
              }
            }
          }
        }
      end
    end
  end
end
