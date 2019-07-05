# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_12_01_8_0
  module Models
    #
    # The results and errors from an execution of a pool autoscale formula.
    #
    #
    class AutoScaleRun

      include MsRestAzure

      # @return [DateTime] The time at which the autoscale formula was last
      # evaluated.
      attr_accessor :timestamp

      # @return [String] The final values of all variables used in the
      # evaluation of the autoscale formula. Each variable value is returned in
      # the form $variable=value, and variables are separated by semicolons.
      attr_accessor :results

      # @return [AutoScaleRunError] Details of the error encountered evaluating
      # the autoscale formula on the pool, if the evaluation was unsuccessful.
      attr_accessor :error


      #
      # Mapper for AutoScaleRun class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'AutoScaleRun',
          type: {
            name: 'Composite',
            class_name: 'AutoScaleRun',
            model_properties: {
              timestamp: {
                client_side_validation: true,
                required: true,
                serialized_name: 'timestamp',
                type: {
                  name: 'DateTime'
                }
              },
              results: {
                client_side_validation: true,
                required: false,
                serialized_name: 'results',
                type: {
                  name: 'String'
                }
              },
              error: {
                client_side_validation: true,
                required: false,
                serialized_name: 'error',
                type: {
                  name: 'Composite',
                  class_name: 'AutoScaleRunError'
                }
              }
            }
          }
        }
      end
    end
  end
end
