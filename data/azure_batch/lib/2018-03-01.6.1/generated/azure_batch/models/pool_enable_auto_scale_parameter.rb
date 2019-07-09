# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_03_01_6_1
  module Models
    #
    # Options for enabling automatic scaling on a pool.
    #
    #
    class PoolEnableAutoScaleParameter

      include MsRestAzure

      # @return [String] The formula for the desired number of compute nodes in
      # the pool. The formula is checked for validity before it is applied to
      # the pool. If the formula is not valid, the Batch service rejects the
      # request with detailed error information. For more information about
      # specifying this formula, see Automatically scale compute nodes in an
      # Azure Batch pool
      # (https://azure.microsoft.com/en-us/documentation/articles/batch-automatic-scaling).
      attr_accessor :auto_scale_formula

      # @return [Duration] The time interval at which to automatically adjust
      # the pool size according to the autoscale formula. The default value is
      # 15 minutes. The minimum and maximum value are 5 minutes and 168 hours
      # respectively. If you specify a value less than 5 minutes or greater
      # than 168 hours, the Batch service rejects the request with an invalid
      # property value error; if you are calling the REST API directly, the
      # HTTP status code is 400 (Bad Request). If you specify a new interval,
      # then the existing autoscale evaluation schedule will be stopped and a
      # new autoscale evaluation schedule will be started, with its starting
      # time being the time when this request was issued.
      attr_accessor :auto_scale_evaluation_interval


      #
      # Mapper for PoolEnableAutoScaleParameter class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'PoolEnableAutoScaleParameter',
          type: {
            name: 'Composite',
            class_name: 'PoolEnableAutoScaleParameter',
            model_properties: {
              auto_scale_formula: {
                client_side_validation: true,
                required: false,
                serialized_name: 'autoScaleFormula',
                type: {
                  name: 'String'
                }
              },
              auto_scale_evaluation_interval: {
                client_side_validation: true,
                required: false,
                serialized_name: 'autoScaleEvaluationInterval',
                type: {
                  name: 'TimeSpan'
                }
              }
            }
          }
        }
      end
    end
  end
end