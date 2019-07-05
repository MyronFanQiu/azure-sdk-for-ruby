# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_03_01_6_1
  module Models
    #
    # The set of changes to be made to a job.
    #
    #
    class JobPatchParameter

      include MsRestAzure

      # @return [Integer] The priority of the job. Priority values can range
      # from -1000 to 1000, with -1000 being the lowest priority and 1000 being
      # the highest priority. If omitted, the priority of the job is left
      # unchanged.
      attr_accessor :priority

      # @return [OnAllTasksComplete] The action the Batch service should take
      # when all tasks in the job are in the completed state. If omitted, the
      # completion behavior is left unchanged. You may not change the value
      # from terminatejob to noaction - that is, once you have engaged
      # automatic job termination, you cannot turn it off again. If you try to
      # do this, the request fails with an 'invalid property value' error
      # response; if you are calling the REST API directly, the HTTP status
      # code is 400 (Bad Request). Possible values include: 'noAction',
      # 'terminateJob'
      attr_accessor :on_all_tasks_complete

      # @return [JobConstraints] The execution constraints for the job. If
      # omitted, the existing execution constraints are left unchanged.
      attr_accessor :constraints

      # @return [PoolInformation] The pool on which the Batch service runs the
      # job's tasks. You may change the pool for a job only when the job is
      # disabled. The Patch Job call will fail if you include the poolInfo
      # element and the job is not disabled. If you specify an
      # autoPoolSpecification specification in the poolInfo, only the keepAlive
      # property can be updated, and then only if the auto pool has a
      # poolLifetimeOption of job. If omitted, the job continues to run on its
      # current pool.
      attr_accessor :pool_info

      # @return [Array<MetadataItem>] A list of name-value pairs associated
      # with the job as metadata. If omitted, the existing job metadata is left
      # unchanged.
      attr_accessor :metadata


      #
      # Mapper for JobPatchParameter class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'JobPatchParameter',
          type: {
            name: 'Composite',
            class_name: 'JobPatchParameter',
            model_properties: {
              priority: {
                client_side_validation: true,
                required: false,
                serialized_name: 'priority',
                type: {
                  name: 'Number'
                }
              },
              on_all_tasks_complete: {
                client_side_validation: true,
                required: false,
                serialized_name: 'onAllTasksComplete',
                type: {
                  name: 'Enum',
                  module: 'OnAllTasksComplete'
                }
              },
              constraints: {
                client_side_validation: true,
                required: false,
                serialized_name: 'constraints',
                type: {
                  name: 'Composite',
                  class_name: 'JobConstraints'
                }
              },
              pool_info: {
                client_side_validation: true,
                required: false,
                serialized_name: 'poolInfo',
                type: {
                  name: 'Composite',
                  class_name: 'PoolInformation'
                }
              },
              metadata: {
                client_side_validation: true,
                required: false,
                serialized_name: 'metadata',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'MetadataItemElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'MetadataItem'
                      }
                  }
                }
              }
            }
          }
        }
      end
    end
  end
end
