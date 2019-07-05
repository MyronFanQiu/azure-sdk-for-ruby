# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_09_01_6_0
  module Models
    #
    # The set of changes to be made to a job.
    #
    #
    class JobUpdateParameter

      include MsRestAzure

      # @return [Integer] The priority of the job. Priority values can range
      # from -1000 to 1000, with -1000 being the lowest priority and 1000 being
      # the highest priority. If omitted, it is set to the default value 0.
      attr_accessor :priority

      # @return [JobConstraints] The execution constraints for the job. If
      # omitted, the constraints are cleared.
      attr_accessor :constraints

      # @return [PoolInformation] The pool on which the Batch service runs the
      # job's tasks. You may change the pool for a job only when the job is
      # disabled. The Update Job call will fail if you include the poolInfo
      # element and the job is not disabled. If you specify an
      # autoPoolSpecification specification in the poolInfo, only the keepAlive
      # property can be updated, and then only if the auto pool has a
      # poolLifetimeOption of job.
      attr_accessor :pool_info

      # @return [Array<MetadataItem>] A list of name-value pairs associated
      # with the job as metadata. If omitted, it takes the default value of an
      # empty list; in effect, any existing metadata is deleted.
      attr_accessor :metadata

      # @return [OnAllTasksComplete] The action the Batch service should take
      # when all tasks in the job are in the completed state. If omitted, the
      # completion behavior is set to noaction. If the current value is
      # terminatejob, this is an error because a job's completion behavior may
      # not be changed from terminatejob to noaction. You may not change the
      # value from terminatejob to noaction - that is, once you have engaged
      # automatic job termination, you cannot turn it off again. If you try to
      # do this, the request fails and Batch returns status code 400 (Bad
      # Request) and an 'invalid property value' error response. If you do not
      # specify this element in a PUT request, it is equivalent to passing
      # noaction. This is an error if the current value is terminatejob.
      # Possible values include: 'noAction', 'terminateJob'
      attr_accessor :on_all_tasks_complete


      #
      # Mapper for JobUpdateParameter class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'JobUpdateParameter',
          type: {
            name: 'Composite',
            class_name: 'JobUpdateParameter',
            model_properties: {
              priority: {
                client_side_validation: true,
                required: false,
                serialized_name: 'priority',
                type: {
                  name: 'Number'
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
                required: true,
                serialized_name: 'poolInfo',
                default_value: {},
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
              },
              on_all_tasks_complete: {
                client_side_validation: true,
                required: false,
                serialized_name: 'onAllTasksComplete',
                type: {
                  name: 'Enum',
                  module: 'OnAllTasksComplete'
                }
              }
            }
          }
        }
      end
    end
  end
end
