# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_09_01_6_0
  module Models
    #
    # Settings which specify how to run a multi-instance task.

    # Multi-instance tasks are commonly used to support MPI tasks.
    #
    class MultiInstanceSettings

      include MsRestAzure

      # @return [Integer] The number of compute nodes required by the task. If
      # omitted, the default is 1.
      attr_accessor :number_of_instances

      # @return [String] The command line to run on all the compute nodes to
      # enable them to coordinate when the primary runs the main task command.
      # A typical coordination command line launches a background service and
      # verifies that the service is ready to process inter-node messages.
      attr_accessor :coordination_command_line

      # @return [Array<ResourceFile>] A list of files that the Batch service
      # will download before running the coordination command line. The
      # difference between common resource files and task resource files is
      # that common resource files are downloaded for all subtasks including
      # the primary, whereas task resource files are downloaded only for the
      # primary. Also note that these resource files are not downloaded to the
      # task working directory, but instead are downloaded to the task root
      # directory (one directory above the working directory).
      attr_accessor :common_resource_files


      #
      # Mapper for MultiInstanceSettings class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'MultiInstanceSettings',
          type: {
            name: 'Composite',
            class_name: 'MultiInstanceSettings',
            model_properties: {
              number_of_instances: {
                client_side_validation: true,
                required: false,
                serialized_name: 'numberOfInstances',
                type: {
                  name: 'Number'
                }
              },
              coordination_command_line: {
                client_side_validation: true,
                required: true,
                serialized_name: 'coordinationCommandLine',
                type: {
                  name: 'String'
                }
              },
              common_resource_files: {
                client_side_validation: true,
                required: false,
                serialized_name: 'commonResourceFiles',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'ResourceFileElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'ResourceFile'
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
