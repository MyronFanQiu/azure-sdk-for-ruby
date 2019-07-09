# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2019_06_01_9_0
  module Models
    #
    # Information about a Task running on a Compute Node.
    #
    #
    class TaskInformation

      include MsRestAzure

      # @return [String] The URL of the Task.
      attr_accessor :task_url

      # @return [String] The ID of the Job to which the Task belongs.
      attr_accessor :job_id

      # @return [String] The ID of the Task.
      attr_accessor :task_id

      # @return [Integer] The ID of the subtask if the Task is a multi-instance
      # Task.
      attr_accessor :subtask_id

      # @return [TaskState] The current state of the Task. Possible values
      # include: 'active', 'preparing', 'running', 'completed'
      attr_accessor :task_state

      # @return [TaskExecutionInformation] Information about the execution of
      # the Task.
      attr_accessor :execution_info


      #
      # Mapper for TaskInformation class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'TaskInformation',
          type: {
            name: 'Composite',
            class_name: 'TaskInformation',
            model_properties: {
              task_url: {
                client_side_validation: true,
                required: false,
                serialized_name: 'taskUrl',
                type: {
                  name: 'String'
                }
              },
              job_id: {
                client_side_validation: true,
                required: false,
                serialized_name: 'jobId',
                type: {
                  name: 'String'
                }
              },
              task_id: {
                client_side_validation: true,
                required: false,
                serialized_name: 'taskId',
                type: {
                  name: 'String'
                }
              },
              subtask_id: {
                client_side_validation: true,
                required: false,
                serialized_name: 'subtaskId',
                type: {
                  name: 'Number'
                }
              },
              task_state: {
                client_side_validation: true,
                required: true,
                serialized_name: 'taskState',
                type: {
                  name: 'Enum',
                  module: 'TaskState'
                }
              },
              execution_info: {
                client_side_validation: true,
                required: false,
                serialized_name: 'executionInfo',
                type: {
                  name: 'Composite',
                  class_name: 'TaskExecutionInformation'
                }
              }
            }
          }
        }
      end
    end
  end
end